// Package auth handles users, passwords, 2FA, sessions and re-authentication
// (sudo). Policy from [docs/04] and [docs/17 § 1.4].
package auth

import (
	"fmt"
	"time"

	"github.com/JuniorCarlini/hangar/internal/i18n"
)

// Role is a user's role. Order matters: a role covers every role before it.
type Role int

const (
	RoleNone Role = iota // public routes only
	RoleViewer
	RoleOperator
	RoleAdmin
	RoleOwner
)

var roleNames = map[Role]string{
	RoleNone:     "none",
	RoleViewer:   "viewer",
	RoleOperator: "operator",
	RoleAdmin:    "admin",
	RoleOwner:    "owner",
}

// String returns the name stored in the database.
func (r Role) String() string {
	if n, ok := roleNames[r]; ok {
		return n
	}
	return fmt.Sprintf("Role(%d)", int(r))
}

// ParseRole converts the name from the database or the command line.
func ParseRole(s string) (Role, error) {
	for r, n := range roleNames {
		if n == s && r != RoleNone {
			return r, nil
		}
	}
	return RoleNone, i18n.E("user.error.role_unknown", "role", s)
}

// Principal is the authenticated user of a request.
type Principal struct {
	UserID    string
	Role      Role
	SudoUntil time.Time
	// Level is the panel's security level: it decides which actions need
	// SudoUntil to be in the future (see SudoFor).
	Level     Level
	CSRFToken string
	Email     string
	// Name is the display name ("" = not set).
	Name string
	// Locale is the user's chosen language ("" = follow the browser).
	Locale string
	// Theme is "system", "dark" or "light".
	Theme string
	// HasTOTP tells whether the account has 2FA. Without it, sudo asks for
	// the password and the panel shows a banner asking to turn 2FA on.
	HasTOTP bool
	// MustEnroll: the account must have a second factor (RequiredFor) and
	// has none. The session only reaches the enrollment page and logout
	// until it enrolls one.
	MustEnroll bool
	// SessionToken is the cookie's clear-text token, needed to rotate the
	// session on sudo and logout. It is never stored or logged.
	SessionToken string
	// AllProjects is false for a user limited to Projects (slugs): they see
	// only those, and none of the server-wide pages.
	AllProjects bool
	Projects    map[string]bool
}

// CanSeeProject reports whether the user may reach the project.
func (p *Principal) CanSeeProject(slug string) bool {
	return p != nil && (!p.Limited() || p.Projects[slug])
}

// Limited reports whether the user only reaches some projects.
func (p *Principal) Limited() bool { return p != nil && !p.AllProjects && p.Role < RoleAdmin }
