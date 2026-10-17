package projects

import (
	"context"
	"time"

	"github.com/JuniorCarlini/hangar/internal/ids"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// LogMark is a separator a user dropped in a service's log.
type LogMark struct {
	At time.Time
	By string
}

// AddLogMark records a mark now in the service's log.
func (m *Manager) AddLogMark(ctx context.Context, a Actor, serviceID, byName string) (LogMark, error) {
	now := time.Now()
	err := m.q.CreateLogMark(ctx, dbq.CreateLogMarkParams{
		ID: ids.New("lmk_"), ServiceID: serviceID, At: now.UnixNano(), UserID: a.UserID, UserName: byName,
	})
	return LogMark{At: now, By: byName}, err
}

// LogMarks lists the service's marks from since on, oldest first.
func (m *Manager) LogMarks(ctx context.Context, serviceID string, since time.Time) ([]LogMark, error) {
	rows, err := m.q.ListLogMarks(ctx, dbq.ListLogMarksParams{ServiceID: serviceID, At: since.UnixNano()})
	if err != nil {
		return nil, err
	}
	out := make([]LogMark, 0, len(rows))
	for _, r := range rows {
		out = append(out, LogMark{At: time.Unix(0, r.At), By: r.UserName})
	}
	return out, nil
}
