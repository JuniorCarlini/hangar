package archive

import (
	"testing"
	"time"
)

func TestRolesKeyIsNextToTheDump(t *testing.T) {
	at := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	dump := DumpKey(ClassWeekly, "lobot", "db", at)
	roles := RolesKey(dump)
	if roles != "semanal/lobot/db/20261028T120000Z.roles.sql.age" {
		t.Fatalf("roles key: %s", roles)
	}
	o, ok := ParseKey(roles)
	if !ok || o.Kind != KindRoles || o.Class != ClassWeekly || o.Project != "lobot" || o.Service != "db" || !o.Time.Equal(at) {
		t.Fatalf("parse: %+v %v", o, ok)
	}
	// A dump is still a dump: listings of dumps do not pick the roles up.
	if d, _ := ParseKey(dump); d.Kind != KindDump {
		t.Fatalf("dump: %+v", d)
	}
	if RolesKey("wal/x/y/base/a.tar.zst.age") != "" {
		t.Fatal("only dumps have roles")
	}
}
