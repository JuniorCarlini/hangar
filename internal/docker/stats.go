package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"

	"github.com/JuniorCarlini/hangar/internal/node"
)

var _ node.StatsReader = (*Local)(nil)

// ContainerStats takes one reading (stream=false, one-shot) of a container
// Hangar manages. The caller keeps the previous reading to compute rates,
// which avoids the daemon's extra second of waiting per container.
func (l *Local) ContainerStats(ctx context.Context, id string) (node.ContainerStats, error) {
	if _, err := l.inspectManaged(ctx, id); err != nil {
		return node.ContainerStats{}, err
	}
	res, err := l.c.ContainerStats(ctx, id, client.ContainerStatsOptions{})
	if err != nil {
		return node.ContainerStats{}, err
	}
	defer func() { _ = res.Body.Close() }()
	var s container.StatsResponse
	if err := json.NewDecoder(res.Body).Decode(&s); err != nil {
		return node.ContainerStats{}, fmt.Errorf("decode stats: %w", err)
	}
	return statsFrom(s), nil
}

func statsFrom(s container.StatsResponse) node.ContainerStats {
	out := node.ContainerStats{
		CPUTotal:   s.CPUStats.CPUUsage.TotalUsage,
		SystemCPU:  s.CPUStats.SystemUsage,
		OnlineCPUs: int(s.CPUStats.OnlineCPUs),
		MemLimit:   s.MemoryStats.Limit,
		MemUsed:    memUsed(s.MemoryStats),
	}
	if out.OnlineCPUs == 0 {
		out.OnlineCPUs = len(s.CPUStats.CPUUsage.PercpuUsage)
	}
	for _, n := range s.Networks {
		out.NetRx += n.RxBytes
		out.NetTx += n.TxBytes
	}
	return out
}

// memUsed subtracts the inactive page cache, like the docker CLI: cgroup v2
// reports it as inactive_file, cgroup v1 as total_inactive_file.
func memUsed(m container.MemoryStats) uint64 {
	cache := m.Stats["inactive_file"]
	if v, ok := m.Stats["total_inactive_file"]; ok && cache == 0 {
		cache = v
	}
	if cache < m.Usage {
		return m.Usage - cache
	}
	return m.Usage
}

// DiskUsage is "docker system df" for images, volumes, containers and the
// build cache. Verbose: from API 1.52 on, Docker lists each volume (with
// its size) only when asked to; without it the per-volume sizes are empty.
func (l *Local) DiskUsage(ctx context.Context) (node.DiskUsage, error) {
	r, err := l.c.DiskUsage(ctx, client.DiskUsageOptions{Containers: true, Images: true, Volumes: true, BuildCache: true, Verbose: true})
	if err != nil {
		return node.DiskUsage{}, err
	}
	// Sum each service's volumes from the same response (the volumes carry the
	// service id as a label), so no extra Docker call is needed.
	var byService, byVolume map[string]int64
	for _, v := range r.Volumes.Items {
		id := v.Labels[node.LabelServiceID]
		if id == "" || v.UsageData == nil || v.UsageData.Size < 0 {
			continue
		}
		if byService == nil {
			byService, byVolume = map[string]int64{}, map[string]int64{}
		}
		byService[id] += v.UsageData.Size
		byVolume[v.Name] = v.UsageData.Size
	}
	return node.DiskUsage{
		Images: r.Images.TotalSize, Volumes: r.Volumes.TotalSize,
		Containers: r.Containers.TotalSize, BuildCache: r.BuildCache.TotalSize,
		ByService: byService, ByVolume: byVolume,
	}, nil
}

// ReclaimDisk frees disk space that no build needs: BuildKit cache older than
// a week and dangling images older than a day. Both are chosen by age, so a
// running build — which uses recent cache and just-built images — is never
// touched. It never removes tagged hangar images (pruneBuilds handles those)
// or anything in use; Docker refuses those anyway.
func (l *Local) ReclaimDisk(ctx context.Context) (node.Reclaimed, error) {
	var out node.Reclaimed
	var errs []error
	bc, err := l.c.BuildCachePrune(ctx, client.BuildCachePruneOptions{
		Filters: make(client.Filters).Add("until", "168h"),
	})
	if err != nil {
		errs = append(errs, fmt.Errorf("prune build cache: %w", err))
	} else {
		out.BuildCache = int64(bc.Report.SpaceReclaimed) //nolint:gosec // byte count fits in int64
	}
	ip, err := l.c.ImagePrune(ctx, client.ImagePruneOptions{
		Filters: make(client.Filters).Add("dangling", "true").Add("until", "24h"),
	})
	if err != nil {
		errs = append(errs, fmt.Errorf("prune dangling images: %w", err))
	} else {
		out.Images = int64(ip.Report.SpaceReclaimed) //nolint:gosec // byte count fits in int64
	}
	return out, errors.Join(errs...)
}
