package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/JuniorCarlini/hangar/internal/docker"
	"github.com/JuniorCarlini/hangar/internal/ids"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// instanceKey is the setting holding this panel's instance id: generated
// once, kept with the rest of the panel's state (a restored database keeps
// it, so the restored panel recognizes its containers).
const instanceKey = "instance_id"

// InstanceID returns this panel's id, creating it on first use.
func InstanceID(ctx context.Context, q *dbq.Queries) (string, error) {
	raw, err := q.GetSetting(ctx, instanceKey)
	switch {
	case err == nil:
		var id string
		if err := json.Unmarshal([]byte(raw), &id); err != nil || id == "" {
			return "", fmt.Errorf("setting %s: invalid value", instanceKey)
		}
		return id, nil
	case !errors.Is(err, sql.ErrNoRows):
		return "", err
	}
	id := ids.New("hgi_")
	b, _ := json.Marshal(id)
	if err := q.SetSetting(ctx, dbq.SetSettingParams{Key: instanceKey, ValueJson: string(b)}); err != nil {
		return "", err
	}
	return id, nil
}

// adoptFunc recognizes objects created before instance ids by the project
// and service ids in their labels.
func adoptFunc(q *dbq.Queries) docker.AdoptFunc {
	return func(ctx context.Context, projectID, serviceID string) bool {
		if serviceID == "" {
			n, err := q.KnowsProject(ctx, projectID)
			return err == nil && n > 0
		}
		n, err := q.KnowsService(ctx, dbq.KnowsServiceParams{ID: serviceID, ProjectID: projectID})
		return err == nil && n > 0
	}
}

// ConnectDocker connects to Docker as this panel: the node only acts on
// containers, networks and volumes this panel created (docs/05).
func ConnectDocker(ctx context.Context, core *Core, host string) (*docker.Local, error) {
	id, err := InstanceID(ctx, core.Store.Q)
	if err != nil {
		return nil, fmt.Errorf("instance id: %w", err)
	}
	d, err := docker.New(ctx, host)
	if err != nil {
		return nil, err
	}
	d.SetInstance(id, adoptFunc(core.Store.Q))
	return d, nil
}
