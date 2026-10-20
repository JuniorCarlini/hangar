package alerts

import (
	"context"
	"fmt"
	"strings"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// SensitiveActions are the audit actions of routes that need sudo (and the
// lockdown-related channel changes): each one done successfully becomes a
// security alert. A test in web checks every sudo route is listed here.
var SensitiveActions = []string{
	"secret.reveal",
	"service.delete",
	"project.delete",
	"domain.dynamic.enable",
	"domain.dynamic.disable",
	"domain.dynamic.rotate_secret",
	"domain.add",
	"edge.dns.set",
	"domain.remove",
	"port.open",
	"service.endpoint.public",
	"service.endpoint.sslip_on",
	"project.link",
	"service.backup.download",
	"system.update.request",
	"alerts.channel.delete",
	"alerts.channel.toggle",
	"status_link.create",
	"brand.save",
	"service.volume.wipe",
	"service.volume.limit",
	"service.volume.unlimit",
	"service.image.change",
	"service.terminal.open",
	"status_link.revoke",
	"service.git.webhook",
	"backup.key.add",
	"backup.key.confirm",
	"backup.key.remove",
	"backup.restore.start",
	"backup.target.add",
	"backup.target.remove",
	"backup.download_link",
	"user.invite",
	"user.invite.cancel",
	"user.update",
	"user.remove",
	"security.level",
}

// SecurityKinds are the alerts that cannot be turned off.
var SecurityKinds = []string{
	"login_new_ip", "login_failures", "account_locked", "totp_disabled", "sudo_action",
	"user_created", "port_public", "port_unknown", "channel_added", "update_applied", "update_failed",
	"lockdown", "lockdown_released",
}

// Observe hooks the service to the audit log: every committed record is
// checked for security events. The audit call never waits on it.
func (s *Service) Observe(al *audit.Logger) {
	al.Observe(func(e audit.Entry) {
		s.mu.Lock()
		ch := s.events
		s.mu.Unlock()
		if ch == nil {
			// Command line: no background loop, handle it now.
			s.handleEntry(context.Background(), e)
			return
		}
		s.pending.Add(1)
		select {
		case ch <- e:
		default:
			s.pending.Done()
			s.log.Warn("security alert queue full; event dropped", "action", e.Action)
		}
	})
}

func (s *Service) observeLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-s.events:
			s.handleEntry(ctx, e)
			s.pending.Done()
		}
	}
}

func (s *Service) handleEntry(ctx context.Context, e audit.Entry) {
	ev, ok := s.securityEvent(ctx, e)
	if !ok {
		return
	}
	if _, err := s.Notify(ctx, ev); err != nil {
		s.log.Error("raise security alert", "action", e.Action, "error", err)
	}
}

// securityEvent turns an audit record into a security alert, when it is one.
func (s *Service) securityEvent(ctx context.Context, e audit.Entry) (Event, bool) {
	sec := func(kind string, sev Severity, key string, params map[string]string) (Event, bool) {
		if params == nil {
			params = map[string]string{}
		}
		if _, ok := params["user"]; !ok {
			params["user"] = s.userLabel(ctx, e.ActorID)
		}
		return Event{Kind: kind, Severity: sev, Category: Security, Key: kind + "|" + key, Params: params}, true
	}
	summary := func(k string) string {
		if v, ok := e.Summary[k]; ok && v != nil {
			return fmt.Sprint(v)
		}
		return ""
	}

	switch {
	case e.Action == "auth.login.ok" && e.Outcome == audit.OK && e.ActorID != "" && e.IP != "":
		if !s.newLoginIP(ctx, e.ActorID, e.IP) {
			return Event{}, false
		}
		return sec("login_new_ip", Warning, e.ActorID+"|"+e.IP, map[string]string{"ip": e.IP})
	case e.Action == "auth.login.fail" && summary("limit_reached") == "true":
		return sec("login_failures", Warning, e.IP, map[string]string{"ip": e.IP})
	case e.Action == "auth.account.locked":
		return sec("account_locked", Critical, e.ActorID, map[string]string{"ip": e.IP, "min": summary("minutes")})
	case (e.Action == "auth.totp.disable" || e.Action == "auth.totp.reset") && e.Outcome == audit.OK:
		target := e.TargetID
		if target == "" {
			target = e.ActorID
		}
		return sec("totp_disabled", Critical, target, map[string]string{"user": s.userLabel(ctx, target)})
	case e.Action == "user.create" && e.Outcome == audit.OK:
		return sec("user_created", Warning, e.TargetID, map[string]string{"user": s.userLabel(ctx, e.TargetID), "role": summary("role")})
	case e.Action == "port.open" && e.Outcome == audit.OK && summary("access") == "any":
		return sec("port_public", Warning, summary("service")+"|"+summary("host_port"),
			map[string]string{"service": summary("service"), "port": summary("host_port")})
	case e.Action == "system.port.unknown":
		return sec("port_unknown", Critical, summary("port"), map[string]string{"port": summary("port"), "address": summary("address")})
	case e.Action == "alerts.channel.create" && e.Outcome == audit.OK:
		return sec("channel_added", Info, e.TargetID, map[string]string{"channel": summary("name")})
	case e.Action == "system.update.ok":
		return sec("update_applied", Info, e.TargetID, map[string]string{"from": summary("from"), "to": summary("to")})
	case e.Action == "system.update.rolled_back" || e.Action == "system.update.failed":
		return sec("update_failed", Critical, e.TargetID, map[string]string{"from": summary("from"), "to": summary("to")})
	case e.Action == "system.lockdown" && e.Outcome == audit.OK:
		return sec("lockdown", Critical, fmt.Sprint(s.opt.Now().UnixNano()), map[string]string{"via": summary("via")})
	case e.Action == "system.lockdown.release" && e.Outcome == audit.OK:
		return sec("lockdown_released", Warning, fmt.Sprint(s.opt.Now().UnixNano()), map[string]string{"via": summary("via")})
	case e.Outcome == audit.OK && isSensitive(e.Action):
		// A terminal session that ran one command says which (an admin
		// reading the alert should see what was run, not only where).
		target := targetLabel(e)
		if c := summary("command"); c != "" {
			if r := []rune(c); len(r) > 120 {
				c = string(r[:120]) + "…"
			}
			target += ": " + c
		}
		return sec("sudo_action", Warning, e.Action+"|"+e.ActorID+"|"+e.TargetID+"|"+summary("key")+summary("export")+summary("command"),
			map[string]string{"action": strings.ReplaceAll(e.Action, ".", "_"), "target": target})
	}
	return Event{}, false
}

func isSensitive(action string) bool {
	for _, a := range SensitiveActions {
		if a == action {
			return true
		}
	}
	return false
}

// targetLabel names what a sensitive action touched, without secrets.
func targetLabel(e audit.Entry) string {
	for _, k := range []string{"service", "slug", "channel", "key", "export", "version"} {
		if v, ok := e.Summary[k]; ok && v != nil && fmt.Sprint(v) != "" {
			return fmt.Sprint(v)
		}
	}
	if e.TargetID != "" {
		return e.TargetID
	}
	return "—"
}

// userLabel is how alerts name a user: the display name, else the e-mail.
func (s *Service) userLabel(ctx context.Context, id string) string {
	if id == "" {
		return "—"
	}
	u, err := s.q.GetUserByID(ctx, id)
	if err != nil {
		return id
	}
	if u.Name != "" {
		return u.Name + " <" + u.Email + ">"
	}
	return u.Email
}

// newLoginIP remembers the address and reports whether it was new for the
// user.
func (s *Service) newLoginIP(ctx context.Context, userID, ip string) bool {
	now := s.opt.Now().Unix()
	n, err := s.q.RememberLoginIP(ctx, dbq.RememberLoginIPParams{UserID: userID, Ip: ip, FirstAt: now, LastAt: now})
	if err != nil {
		s.log.Warn("remember login address", "error", err)
		return false
	}
	if n == 0 {
		_ = s.q.TouchLoginIP(ctx, dbq.TouchLoginIPParams{LastAt: now, UserID: userID, Ip: ip})
		return false
	}
	return true
}
