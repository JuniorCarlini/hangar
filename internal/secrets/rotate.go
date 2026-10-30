package secrets

import (
	"context"
	"database/sql"
	"fmt"
)

// sealedColumn is one database column encrypted with the master key. ad
// rebuilds the associated data each package uses ("table|id|column"); a
// wrong one fails the rotation before anything is written.
type sealedColumn struct {
	table, column string
	keys          []string // primary key columns, in the WHERE of the update
	ad            func(k []string) string
}

// sealedColumns lists every value encrypted with the master key. A test
// checks every "…AD" helper in the code is covered (TestRotationCoversEveryAD).
var sealedColumns = []sealedColumn{
	{"users", "totp_secret_enc", []string{"id"}, func(k []string) string { return "users|" + k[0] + "|totp_secret_enc" }},
	{"env_vars", "value_enc", []string{"service_id", "key"}, func(k []string) string { return "env_vars|" + k[0] + "|" + k[1] }},
	{"service_exports", "value_enc", []string{"service_id", "key"}, func(k []string) string { return "service_exports|" + k[0] + "|" + k[1] }},
	{"services", "domain_check_secret_enc", []string{"id"}, func(k []string) string { return "services|" + k[0] + "|domain_check_secret" }},
	{"service_env_files", "text_enc", []string{"service_id"}, func(k []string) string { return "services|" + k[0] + "|env_file" }},
	{"alert_channels", "config_enc", []string{"id"}, func(k []string) string { return "alert_channels|" + k[0] + "|config_enc" }},
	{"backup_targets", "config_enc", []string{"id"}, func(k []string) string { return "backup_targets|" + k[0] + "|config" }},
	{"service_git", "token_enc", []string{"service_id"}, func(k []string) string { return "service_git|" + k[0] + "|token" }},
	{"service_git", "webhook_token_enc", []string{"service_id"}, func(k []string) string { return "service_git|" + k[0] + "|webhook_token" }},
	{"git_credentials", "token_enc", []string{"id"}, func(k []string) string { return "git_credentials|" + k[0] + "|token" }},
	{"service_git", "webhook_secret_enc", []string{"service_id"}, func(k []string) string { return "service_git|" + k[0] + "|webhook_secret" }},
	{"edge_settings", "dns_token_enc", []string{"id"}, func(k []string) string { return "edge_settings|" + k[0] + "|dns_token" }},
	{"backup_server_key", "identity_enc", []string{"id"}, func(k []string) string { return "backup_server_key|" + k[0] + "|identity" }},
	{"audit_chain", "key_enc", []string{"version"}, func(k []string) string { return "audit_chain|" + k[0] + "|key" }},
}

// Rotate re-encrypts every secret in the database from oldBox to
// newBox in one transaction: either all of them move to the new key or none
// does. It returns how many values were re-encrypted.
func Rotate(ctx context.Context, db *sql.DB, oldBox, newBox *Box) (int, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	n := 0
	for _, c := range sealedColumns {
		cols := ""
		where := ""
		for i, k := range c.keys {
			if i > 0 {
				cols += ", "
				where += " AND "
			}
			cols += k
			where += k + " = ?"
		}
		items, err := sealedRows(ctx, tx, c, cols)
		if err != nil {
			return 0, err
		}
		for _, it := range items {
			if len(it.sealed) == 0 {
				continue
			}
			ad := c.ad(it.keys)
			plain, err := oldBox.Open(it.sealed, ad)
			if err != nil {
				return 0, fmt.Errorf("%s.%s (%v): %w", c.table, c.column, it.keys, err)
			}
			resealed, err := newBox.Seal(plain, ad)
			if err != nil {
				return 0, err
			}
			args := append([]any{resealed}, toAny(it.keys)...)
			if _, err := tx.ExecContext(ctx, "UPDATE "+c.table+" SET "+c.column+" = ? WHERE "+where, args...); err != nil { //nolint:gosec // identifiers from a fixed list
				return 0, err
			}
			n++
		}
	}
	return n, tx.Commit()
}

type sealedItem struct {
	keys   []string
	sealed []byte
}

// sealedRows reads every non-empty value of a column with its keys.
func sealedRows(ctx context.Context, tx *sql.Tx, c sealedColumn, cols string) ([]sealedItem, error) {
	// Table and column names come from the fixed list above.
	rows, err := tx.QueryContext(ctx, "SELECT "+cols+", "+c.column+" FROM "+c.table+" WHERE "+c.column+" IS NOT NULL") //nolint:gosec // identifiers from a fixed list
	if err != nil {
		return nil, fmt.Errorf("%s.%s: %w", c.table, c.column, err)
	}
	defer func() { _ = rows.Close() }()
	var items []sealedItem
	for rows.Next() {
		keys := make([]string, len(c.keys))
		dest := make([]any, 0, len(keys)+1)
		for i := range keys {
			dest = append(dest, &keys[i])
		}
		var sealed []byte
		dest = append(dest, &sealed)
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		items = append(items, sealedItem{keys, sealed})
	}
	return items, rows.Err()
}

func toAny(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}
