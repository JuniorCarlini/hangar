package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// Level is how often the panel asks for the password again after login.
// The owner picks it: someone alone on their own computer does not need
// the same friction as a team on a server with sensitive data.
type Level string

const (
	// LevelBasic asks only at login; dangerous actions keep their typed
	// confirmation.
	LevelBasic Level = "basic"
	// LevelStandard asks again only for what cannot be undone or shows a
	// secret.
	LevelStandard Level = "standard"
	// LevelStrict asks again for every sensitive action, with a short window.
	LevelStrict Level = "strict"
)

// DefaultLevel is the level of a panel that never chose one.
const DefaultLevel = LevelStandard

// Levels lists the levels from the least to the most strict.
var Levels = []Level{LevelBasic, LevelStandard, LevelStrict}

// ErrUnknownLevel refuses a level that is not one of Levels.
var ErrUnknownLevel = &i18n.Error{Key: "security.error.level"}

const levelKey = "security.level"

// SudoTier says which levels make a route ask for the password again.
type SudoTier int

const (
	// SudoNone never asks.
	SudoNone SudoTier = iota
	// SudoStrict asks only at LevelStrict: actions that open a way in or
	// change how the panel looks, guarded by their confirmation otherwise.
	SudoStrict
	// SudoCritical asks at LevelStandard and LevelStrict: deleting data,
	// revealing secrets, the terminal, backups and the team.
	SudoCritical
	// SudoAlways asks at every level: lowering the level itself, or whoever
	// finds the panel open would just turn the protection off first.
	SudoAlways
)

// Requires reports whether the level asks for the password on tier t.
func (l Level) Requires(t SudoTier) bool {
	switch t {
	case SudoAlways:
		return true
	case SudoCritical:
		return l != LevelBasic
	case SudoStrict:
		return l == LevelStrict
	}
	return false
}

// SudoTTL is how long a confirmation lasts at this level.
func (l Level) SudoTTL() time.Duration {
	if l == LevelStandard {
		return 30 * time.Minute
	}
	return SudoTTL
}

// SessionIdle is how long a session survives without use at this level.
// Basic keeps the person in until the absolute SessionMax.
func (l Level) SessionIdle() time.Duration {
	switch l {
	case LevelBasic:
		return SessionMax
	case LevelStandard:
		return 2 * time.Hour
	}
	return SessionIdle
}

// Valid reports whether l is one of Levels.
func (l Level) Valid() bool {
	for _, v := range Levels {
		if l == v {
			return true
		}
	}
	return false
}

// SudoFor reports whether the request may run an action of tier t: either
// the level does not ask for it or the person confirmed recently.
func (p *Principal) SudoFor(t SudoTier, now time.Time) bool {
	return !p.Level.Requires(t) || now.Before(p.SudoUntil)
}

type levelSetting struct {
	Level Level `json:"level"`
}

// Level returns the panel's security level, from memory after the first
// read: only SetLevel changes it.
func (s *Service) Level(ctx context.Context) Level {
	s.levelMu.Lock()
	defer s.levelMu.Unlock()
	if s.level != "" {
		return s.level
	}
	l := DefaultLevel
	raw, err := s.q.GetSetting(ctx, levelKey)
	switch {
	case err == nil:
		var v levelSetting
		if json.Unmarshal([]byte(raw), &v) == nil && v.Level.Valid() {
			l = v.Level
		}
	case !errors.Is(err, sql.ErrNoRows):
		// Do not cache a guess: the next request reads again.
		return DefaultLevel
	}
	s.level = l
	return l
}

// SetLevel changes the panel's security level.
func (s *Service) SetLevel(ctx context.Context, userID string, l Level, c Client) error {
	if !l.Valid() {
		return ErrUnknownLevel
	}
	old := s.Level(ctx)
	raw, _ := json.Marshal(levelSetting{Level: l})
	if err := s.q.SetSetting(ctx, dbq.SetSettingParams{Key: levelKey, ValueJson: string(raw)}); err != nil {
		return err
	}
	s.levelMu.Lock()
	s.level = l
	s.levelMu.Unlock()
	s.record(ctx, audit.Entry{
		ActorID: userID, IP: c.IP, Action: "security.level", Outcome: audit.OK,
		Summary: map[string]any{"from": string(old), "to": string(l)},
	})
	return nil
}
