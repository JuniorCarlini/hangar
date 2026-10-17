package node

import "testing"

func TestReservedMount(t *testing.T) {
	for p, want := range map[string]string{
		"/data":                       "",
		"/var/lib/postgresql/data":    "",
		"/usr/share/nginx/html":       "",
		"/usr/share/nginx/html/media": "",
		"/usr/local/apache2/htdocs":   "",
		"/usr":                        "/usr",
		"/usr/share":                  "/usr",
		"/usr/local":                  "/usr",
		"/usr/bin":                    "/usr",
		"/usr/local/bin":              "/usr",
		"/usr/local/lib/x":            "/usr",
		"/etc/nginx":                  "/etc",
		"/run/secrets":                "/run",
		"/var/run":                    "/var/run",
		"/proc":                       "/proc",
		"/lib64":                      "/lib64",
	} {
		if got := ReservedMount(p); got != want {
			t.Errorf("ReservedMount(%q) = %q, want %q", p, got, want)
		}
	}
}
