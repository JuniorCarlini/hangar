package views

import (
	"context"
	"strings"
	"testing"
)

// The connector fills a field only when the name is certain; otherwise the
// field is empty and the usual name is only a hint.
func TestConnectorFillsOnlyWhatIsCertain(t *testing.T) {
	d := ServiceData{Project: "lab", Slug: "app", CSRF: "tok", CanOperate: true, ConnectOffers: []ConnectOffer{
		{Service: "postgres", Key: "HOST", Var: "DB_HOST", Known: true},
		{Service: "postgres", Key: "PASSWORD", Var: "DB_PASSWORD", Secret: true},
	}}
	var b strings.Builder
	if err := connectorDialog(d).Render(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	if !strings.Contains(html, `data-key="HOST" value="DB_HOST" placeholder="DB_HOST"`) {
		t.Error("a certain name is not filled in")
	}
	if !strings.Contains(html, `data-key="PASSWORD" placeholder="DB_PASSWORD"`) {
		t.Error("an uncertain name is filled in instead of hinted")
	}
}

// A template's export that only repeats a variable becomes a tag on it;
// what only the panel computes stays a row of its own.
func TestMergeExportsKeepsOneRowPerValue(t *testing.T) {
	env := []EnvRow{{Key: "POSTGRES_DB", Value: "app"}, {Key: "POSTGRES_USER", Value: "app"}, {Key: "POSTGRES_PASSWORD", Value: "s3cret"}}
	exports := []ExportRow{
		{Key: "DATABASE_URL", Value: "postgres://app:s3cret@db:5432/app"},
		{Key: "HOST", Value: "db"},
		{Key: "PORT", Value: "5432"},
		{Key: "USER", Value: "app"},
		{Key: "DATABASE", Value: "app"},
		{Key: "PASSWORD", Value: "s3cret"},
	}
	rest := MergeExports(env, exports)
	var left []string
	for _, e := range rest {
		left = append(left, e.Key)
	}
	if strings.Join(left, ",") != "DATABASE_URL,HOST,PORT" {
		t.Errorf("rows left = %v", left)
	}
	for i, want := range []string{"DATABASE", "USER", "PASSWORD"} {
		if len(env[i].Aliases) != 1 || env[i].Aliases[0] != want {
			t.Errorf("%s aliases = %v, want %s", env[i].Key, env[i].Aliases, want)
		}
	}
}
