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
