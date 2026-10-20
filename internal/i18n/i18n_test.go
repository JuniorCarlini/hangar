package i18n

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestCatalogsLoad(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	if got := Locales(); len(got) < 2 || got[0] != Default {
		t.Fatalf("Locales() = %v", got)
	}
}

// Every language must have exactly the keys of the default one: a missing
// key would show the raw key on screen.
func TestEveryLocaleHasEveryKey(t *testing.T) {
	want := Keys(Default)
	for _, l := range Locales() {
		got := Keys(l)
		for _, k := range want {
			if !slices.Contains(got, k) {
				t.Errorf("%s: missing key %s", l, k)
			}
		}
		for _, k := range got {
			if !slices.Contains(want, k) {
				t.Errorf("%s: key %s does not exist in %s", l, k, Default)
			}
		}
		for _, k := range got {
			a, b := catalog(Default)[k], catalog(l)[k]
			if (a.text == "") != (b.text == "") {
				t.Errorf("%s: key %s is plural in one language and plain in the other", l, k)
			}
			if placeholders(a) != placeholders(b) {
				t.Errorf("%s: key %s has placeholders %q, want %q", l, k, placeholders(b), placeholders(a))
			}
		}
	}
}

var placeholderRE = regexp.MustCompile(`\{[a-z_]+\}`)

func placeholders(e entry) string {
	all := placeholderRE.FindAllString(e.text+e.one+e.other, -1)
	slices.Sort(all)
	return strings.Join(slices.Compact(all), ",")
}

func TestTranslateInterpolateAndPlural(t *testing.T) {
	ctx := WithLocale(context.Background(), "en")
	if got := T(ctx, "login.step", "n", 1, "total", 2); got != "Step 1 of 2" {
		t.Errorf("interpolation: %q", got)
	}
	if got := T(ctx, "canvas.domains", "n", int64(1)); got != "1 domain" {
		t.Errorf("plural one: %q", got)
	}
	if got := T(ctx, "canvas.domains", "n", 3); got != "3 domains" {
		t.Errorf("plural other: %q", got)
	}
	if got := Tl("pt-BR", "canvas.domains", "n", 0); got != "0 domínios" {
		t.Errorf("pt-BR plural zero: %q", got)
	}
	if got := Tl("en", "does.not.exist"); got != "does.not.exist" {
		t.Errorf("missing key: %q", got)
	}
	if got := Tl("fr", "nav.logout"); got != Tl(Default, "nav.logout") {
		t.Errorf("unknown locale should fall back to the default: %q", got)
	}
}

func TestMatchAndNormalize(t *testing.T) {
	cases := map[string]string{
		"en-US,en;q=0.9,pt-BR;q=0.8": "en",
		"pt-PT,pt;q=0.9":             "pt-BR",
		"fr-FR,de;q=0.9":             Default,
		"":                           Default,
		"de;q=0.5, en;q=0.4":         "en",
	}
	for in, want := range cases {
		if got := Match(in); got != want {
			t.Errorf("Match(%q) = %q, want %q", in, got, want)
		}
	}
	env := map[string]string{"LANG": "en_US.UTF-8"}
	if got := FromEnv(func(k string) string { return env[k] }); got != "en" {
		t.Errorf("FromEnv = %q", got)
	}
	if got := FromEnv(func(string) string { return "C" }); got != Default {
		t.Errorf("FromEnv(C) = %q", got)
	}
}

func TestMessageTranslatesJoinedErrors(t *testing.T) {
	err := errors.Join(E("config.error.required", "field", "data_dir"), errors.New("plain"))
	got := Message("en", err)
	if got != "data_dir is required.\nplain" {
		t.Errorf("Message = %q", got)
	}
	if E("password.common").Error() != Tl("en", "password.common") {
		t.Error("Error() should render English for logs")
	}
}

// dynamicPrefixes are keys built at runtime from stored values; each listed
// value must exist in the catalog.
var dynamicPrefixes = map[string][]string{
	"state.":               {"running", "deploying", "restarting", "exited", "dead", "created", "paused", "removing", "missing", "failed", "unknown"},
	"deploy.status.":       {"live", "running", "failed", "superseded"},
	"deploy.trigger.":      {"create", "manual", "webhook", "rollback", "ports", "restore", "rebuild", "image"},
	"update.state.":        {"ok", "rolled_back", "failed", "applying"},
	"team.role_can.":       {"owner", "admin", "operator", "viewer"},
	"team.role_short.":     {"owner", "admin", "operator", "viewer"},
	"role.":                {"owner", "admin", "operator", "viewer"},
	"errorpage.":           {"not_found.title", "not_found.text", "forbidden.title", "forbidden.text", "too_many.title", "too_many.text", "server.title", "server.text", "other.title", "other.text"},
	"theme.":               {"system", "dark", "light"},
	"security.":            {"basic.name", "basic.for", "basic.asks", "basic.window", "basic.idle", "standard.name", "standard.for", "standard.asks", "standard.window", "standard.idle", "strict.name", "strict.for", "strict.asks", "strict.window", "strict.idle"},
	"canvas.kind.":         {"app", "db", "cache"},
	"compose.kind.":        {"template", "image", "git", "skip"},
	"port.access.":         {"any", "ips", "localhost"},
	"deploy.phase.":        {"clone", "build", "pull", "predeploy", "start", "health", "validate", "switch", "restore"},
	"template.category.":   {"database", "cache", "queue", "search", "storage", "automation", "monitoring", "admin", "other"},
	"service.tab.":         {"overview", "variables", "network", "logs", "settings", "backups"},
	"activity.drift_kind.": {"orphan", "stopped", "missing"},
	"period.":              {"1h", "24h", "7d", "90d"},
	"brand.kind.":          {"down", "deploy", "timeout", "unknown", "maint", "https"},
	"brand.when.":          {"down", "deploy", "timeout", "unknown", "maint", "https"},
	"brand.themes.":        {"auto", "light", "dark"},
	// errpages.Error carries these keys (shown by the brand settings).
	"brand.error.": {"name", "contact", "color", "theme", "logo", "logo_size", "logo_dimensions", "page", "too_long"},
	"flash.": {
		"deploy", "image", "env", "env-deleted", "action", "domain", "domain-deleted", "dynamic-on", "dynamic-off", "dns-token", "port", "port-closed", "rollback", "deploy-settings",
		"git", "git-token", "webhook-off", "maintenance-on", "maintenance-off", "backup-policy", "backup-queued", "backup-preparing", "restore-started", "volume", "volume-removed", "volume-limit", "volume-unlimit",
	},
	"flash.backups.":         {"key-added", "key-confirmed", "key-deleted", "target-added", "target-checked", "target-deleted", "panel-queued"},
	"backups.kind.":          {"pg_dump", "pg_base", "panel"},
	"backups.trigger.":       {"schedule", "manual", "download", "pre_restore", "wal_start", "change"},
	"backups.class.":         {"daily", "weekly", "monthly"},
	"backups.run_status.":    {"running", "ok", "failed"},
	"backups.warning.":       {"shrank", "grew", "rows_dropped"},
	"backups.alert.":         {"stale", "failed", "wal_lag", "wal_restart", "wal_failing", "target_error"},
	"backups.rules.folders.": {"diario", "semanal", "mensal", "wal", "painel"},
	"svcbackup.step.":        {"queued", "pre_backup", "create", "deploy", "plan", "stop", "stage", "recover", "restore", "done"},
	"target.providers.":      {"b2", "wasabi", "aws", "r2", "custom"},
	"domain.reason.":         {"fixed_domain", "wildcard_domain", "app_authorized", "invalid_hostname", "blocked", "no_dynamic_service", "rate_limited", "app_denied", "app_error", "app_bad_signature", "dns_mismatch", "internal_error"},
	"audit.tamper.":          {"removed_or_reordered", "content_changed"},
	"pista.tone.":            {"default", "info", "success", "warning", "danger"},
	"pista.alert.":           {"info", "success", "warning", "danger"},
	"pista.toast.":           {"info", "success", "warning", "danger"},
	"deps.kind.":             {"vuln", "patch", "minor", "major"},
	"deps.kind_short.":       {"patch", "minor", "major"},
	"deps.sev.":              {"critical", "high", "medium", "low", "unknown"},
	"deps.bucket.":           {"deploy", "tag", "code", "wait", "updates"},
	"deps.bucket_sub.":       {"deploy", "tag", "code", "wait"},
	"deps.bucket_hint.":      {"deploy", "tag", "code", "wait", "updates"},
	"status.state.":          {"running", "degraded", "stopped"},
	"statuslink.naming.":     {"alias", "generic", "hidden"},
	"alert.title.":           {"test", "deps", "container_down", "restart_loop", "oom", "service_memory", "host_cpu", "host_memory", "host_disk", "volume_disk", "volume_full", "login_new_ip", "login_failures", "account_locked", "totp_disabled", "sudo_action", "user_created", "port_public", "port_unknown", "channel_added", "update_applied", "update_failed", "lockdown", "lockdown_released", "deploy_failed"},
	"alert.text.":            {"test", "deps", "container_down", "restart_loop", "oom", "service_memory", "host_cpu", "host_memory", "host_disk", "volume_disk", "volume_full", "login_new_ip", "login_failures", "account_locked", "totp_disabled", "sudo_action", "user_created", "port_public", "port_unknown", "channel_added", "update_applied", "update_failed", "lockdown", "lockdown_released", "deploy_failed"},
	"alert.previous.":        {"live", "restored", "down", "none"},
	"alert.action.":          {"secret_reveal", "service_delete", "project_delete", "domain_dynamic_enable", "domain_dynamic_disable", "domain_dynamic_rotate_secret", "domain_add", "edge_dns_set", "domain_remove", "service_endpoint_public", "service_endpoint_sslip_on", "port_open", "project_link", "service_backup_download", "system_update_request", "alerts_channel_delete", "alerts_channel_toggle", "status_link_create", "status_link_revoke", "service_git_webhook", "backup_key_add", "backup_key_confirm", "backup_key_remove", "backup_restore_start", "backup_target_add", "backup_target_remove", "backup_download_link", "brand_save", "service_volume_wipe", "service_volume_limit", "service_volume_unlimit", "service_image_change", "service_terminal_open", "user_invite", "user_invite_cancel", "user_update", "user_remove", "security_level"},
	"alerts.flash.":          {"channel-added", "channel-deleted", "channel-paused", "channel-resumed", "tested", "rules", "muted", "unmuted"},
	"alerts.kind.":           {"telegram", "email", "webhook"},
	"alerts.new.":            {"telegram", "email", "webhook"},
	"alerts.receives.":       {"info", "warning", "critical"},
	"alerts.level.":          {"info", "warning", "critical"},
	"alerts.status.":         {"sent", "failed", "dropped"},
	"alerts.rule.":           {"container_down", "restart_loop", "oom", "service_memory", "host_cpu", "host_memory", "host_disk", "volume_disk", "volume_full"},
	"alerts.rule_desc.":      {"container_down", "restart_loop", "oom", "service_memory", "host_cpu", "host_memory", "host_disk", "volume_disk", "volume_full"},
	"locale.":                nil, // one per catalog, checked below
}

var keyUseRE = regexp.MustCompile(`(?:\bt\(ctx, |i18n\.T\([A-Za-z.]+(?:\(\))?, |i18n\.Tl\([A-Za-z.]+(?:\(\))?, |\btr\(|i18n\.E\(|i18n\.Error\{Key: )"([a-z0-9_.-]+)"`)

// Every key used in the code exists, and every key in the catalog is used:
// no raw keys on screen, no dead text piling up.
func TestKeysUsedMatchCatalog(t *testing.T) {
	used := map[string]bool{}
	for _, dir := range []string{"../../internal", "../../cmd"} {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			if strings.HasSuffix(path, "_templ.go") || strings.HasSuffix(path, "_test.go") ||
				(!strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, ".templ")) {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, m := range keyUseRE.FindAllStringSubmatch(string(b), -1) {
				used[m[1]] = true
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for prefix, values := range dynamicPrefixes {
		if prefix == "locale." {
			for _, l := range Locales() {
				used[prefix+l] = true
			}
			continue
		}
		for _, v := range values {
			used[prefix+v] = true
		}
	}
	catalogKeys := Keys(Default)
	for k := range used {
		if strings.HasSuffix(k, ".") { // a prefix completed at runtime
			if _, ok := dynamicPrefixes[k]; !ok {
				t.Errorf("dynamic key prefix %q is not listed in dynamicPrefixes", k)
			}
			continue
		}
		if !slices.Contains(catalogKeys, k) {
			t.Errorf("key %q is used in the code but missing from the catalog", k)
		}
	}
	for _, k := range catalogKeys {
		if !used[k] {
			t.Errorf("key %q is in the catalog but never used", k)
		}
	}
}

func TestNestedErrorUsesSameLanguage(t *testing.T) {
	inner := E("config.error.listen_name")
	outer := E("config.error.listen", "addr", "localhost:7700", "error", inner)
	if got := Message("pt-BR", outer); !strings.Contains(got, Tl("pt-BR", "config.error.listen_name")) {
		t.Errorf("nested error should be in pt-BR: %q", got)
	}
}
