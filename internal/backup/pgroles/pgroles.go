// Package pgroles finds the database roles a pg_dump refers to, so a
// restore into a fresh PostgreSQL can create the missing ones first.
//
// Roles live in the cluster, not in the database: pg_dump of one database
// keeps the GRANTs, row-level security policies and default privileges
// that name them, but not the roles. Restoring with those statements into
// a server where the roles do not exist fails ("role ... does not exist"),
// so the roles are created beforehand without a password (NOLOGIN), and
// everything that refers to them applies as it did in the original.
package pgroles

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// MaxScript bounds the SQL kept from a dump's ACL, POLICY and DEFAULT ACL
// entries (the rest of the script is read and dropped).
const MaxScript = 64 << 20

// sectionRE reads the entry type from the comment pg_restore writes above
// each entry: "-- Name: TABLE t; Type: ACL; Schema: public; Owner: x".
var sectionRE = regexp.MustCompile(`; Type: ([A-Z ]+); Schema: `)

// kept are the entry types that name roles once ownership is skipped
// (--no-owner).
var kept = map[string]bool{"ACL": true, "POLICY": true, "DEFAULT ACL": true}

// FromScript reads a SQL script written by pg_restore (-f) and returns the
// roles its ACL, POLICY and DEFAULT ACL entries name, in order of first
// appearance, without PUBLIC, the CURRENT_USER-like forms and the
// predefined pg_* roles.
func FromScript(r io.Reader) ([]string, error) {
	var sql strings.Builder
	keep := false
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			switch {
			case strings.HasPrefix(line, "-- Name: ") || strings.HasPrefix(line, "-- Data for Name: "):
				keep = false
				if m := sectionRE.FindAllStringSubmatch(line, -1); m != nil && strings.HasPrefix(line, "-- Name: ") {
					keep = kept[m[len(m)-1][1]]
				}
			case strings.HasPrefix(line, `\`):
				// psql meta-commands (\restrict, \connect) are not SQL.
			case keep:
				if sql.Len()+len(line) > MaxScript {
					return nil, errors.New("the dump's permissions are too large to read")
				}
				sql.WriteString(line)
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return FromSQL(sql.String()), nil
}

// FromSQL returns the roles named by the GRANT, REVOKE, ALTER DEFAULT
// PRIVILEGES, CREATE/ALTER POLICY and SET SESSION AUTHORIZATION
// statements in sql, in order of first appearance.
func FromSQL(sql string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(name string) {
		if name == "" || seen[name] || skip(name) {
			return
		}
		seen[name] = true
		out = append(out, name)
	}
	for _, st := range statements(tokenize(sql)) {
		for _, name := range rolesOf(st) {
			add(name)
		}
	}
	return out
}

// skip reports names that are not roles to create: PUBLIC and the
// session forms are keywords, pg_* are reserved for predefined roles.
func skip(name string) bool {
	switch name {
	case "public", "current_user", "session_user", "current_role":
		return true
	}
	return strings.HasPrefix(name, "pg_")
}

// --- tokens ---------------------------------------------------------------

type tokKind int

const (
	tWord   tokKind = iota // unquoted identifier or keyword, lowercased
	tQuoted                // "quoted identifier", as written
	tString                // 'string literal' (and E'', $$ $$)
	tPunct                 // one character
)

type token struct {
	kind tokKind
	text string
	// depth is the parenthesis nesting the token sits in.
	depth int
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9') || c == '$'
}

// tokenize splits SQL into tokens, dropping whitespace and comments.
func tokenize(s string) []token {
	var out []token
	depth := 0
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f':
			i++
		case c == '-' && i+1 < len(s) && s[i+1] == '-':
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			// Block comments nest in PostgreSQL.
			n := 0
			for i < len(s) {
				if strings.HasPrefix(s[i:], "/*") {
					n++
					i += 2
				} else if strings.HasPrefix(s[i:], "*/") {
					n--
					i += 2
					if n == 0 {
						break
					}
				} else {
					i++
				}
			}
		case c == '"':
			text, n := quoted(s[i:], '"', false)
			out = append(out, token{kind: tQuoted, text: text, depth: depth})
			i += n
		case c == '\'':
			text, n := quoted(s[i:], '\'', false)
			out = append(out, token{kind: tString, text: text, depth: depth})
			i += n
		case (c == 'e' || c == 'E') && i+1 < len(s) && s[i+1] == '\'':
			text, n := quoted(s[i+1:], '\'', true)
			out = append(out, token{kind: tString, text: text, depth: depth})
			i += 1 + n
		case c == '$' && dollarTag(s[i:]) != "":
			tag := dollarTag(s[i:])
			body := s[i+len(tag):]
			end := strings.Index(body, tag)
			if end < 0 {
				out = append(out, token{kind: tString, text: body, depth: depth})
				i = len(s)
				continue
			}
			out = append(out, token{kind: tString, text: body[:end], depth: depth})
			i += len(tag) + end + len(tag)
		case isIdentStart(c):
			j := i + 1
			for j < len(s) && isIdentPart(s[j]) {
				j++
			}
			out = append(out, token{kind: tWord, text: asciiLower(s[i:j]), depth: depth})
			i = j
		default:
			if c == ')' && depth > 0 {
				depth--
			}
			out = append(out, token{kind: tPunct, text: string(c), depth: depth})
			if c == '(' {
				depth++
			}
			i++
		}
	}
	return out
}

// quoted reads a quoted run starting at s[0] (the quote), where a doubled
// quote stands for one; backslash escapes count when escapes is set. It
// returns the unquoted text and the bytes consumed.
func quoted(s string, q byte, escapes bool) (string, int) {
	var b strings.Builder
	i := 1
	for i < len(s) {
		c := s[i]
		switch {
		case escapes && c == '\\' && i+1 < len(s):
			b.WriteByte(s[i+1])
			i += 2
		case c == q && i+1 < len(s) && s[i+1] == q:
			b.WriteByte(q)
			i += 2
		case c == q:
			return b.String(), i + 1
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String(), i
}

// dollarTag returns the "$tag$" opening a dollar-quoted string at s, or "".
func dollarTag(s string) string {
	if len(s) > 1 && s[1] == '$' {
		return "$$"
	}
	if len(s) < 2 || !isIdentStart(s[1]) {
		return ""
	}
	for j := 2; j < len(s); j++ {
		switch {
		case s[j] == '$':
			return s[:j+1]
		case !isIdentPart(s[j]):
			return ""
		}
	}
	return ""
}

// asciiLower folds an unquoted identifier the way PostgreSQL does in UTF-8
// databases: ASCII letters only.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// statements splits tokens at the top-level semicolons.
func statements(toks []token) [][]token {
	var out [][]token
	start := 0
	for i, t := range toks {
		if t.kind == tPunct && t.text == ";" && t.depth == 0 {
			if i > start {
				out = append(out, toks[start:i])
			}
			start = i + 1
		}
	}
	if start < len(toks) {
		out = append(out, toks[start:])
	}
	return out
}

// --- statements -----------------------------------------------------------

func kw(st []token, i int, words ...string) bool {
	for k, w := range words {
		if i+k >= len(st) || st[i+k].kind != tWord || st[i+k].text != w || st[i+k].depth != 0 {
			return false
		}
	}
	return true
}

// find returns the index of the first top-level keyword w at or after i,
// or -1.
func find(st []token, i int, w string) int {
	for ; i < len(st); i++ {
		if kw(st, i, w) {
			return i
		}
	}
	return -1
}

// name reads a role name (identifier or quoted identifier) at i.
func name(st []token, i int) (string, bool) {
	if i >= len(st) || st[i].depth != 0 {
		return "", false
	}
	switch st[i].kind {
	case tWord, tQuoted:
		return st[i].text, true
	}
	return "", false
}

// roleList reads "[GROUP] role [, [GROUP] role ...]" at i and returns the
// names and the index after the list.
func roleList(st []token, i int) ([]string, int) {
	var out []string
	for {
		if kw(st, i, "group") {
			if _, ok := name(st, i+1); ok {
				i++
			}
		}
		n, ok := name(st, i)
		if !ok {
			return out, i
		}
		out = append(out, n)
		i++
		if i < len(st) && st[i].kind == tPunct && st[i].text == "," && st[i].depth == 0 {
			i++
			continue
		}
		return out, i
	}
}

// grantedBy adds the role of a "GRANTED BY role" clause.
func grantedBy(st []token, from int) []string {
	if i := find(st, from, "granted"); i >= 0 && kw(st, i+1, "by") {
		if n, ok := name(st, i+2); ok {
			return []string{n}
		}
	}
	return nil
}

// rolesOf returns the role names one statement refers to.
func rolesOf(st []token) []string {
	switch {
	case kw(st, 0, "grant"), kw(st, 0, "revoke"):
		return grantRoles(st)
	case kw(st, 0, "alter", "default", "privileges"):
		var out []string
		i := 3
		for i < len(st) {
			switch {
			case kw(st, i, "for", "role"), kw(st, i, "for", "user"):
				names, next := roleList(st, i+2)
				out = append(out, names...)
				i = next
			case kw(st, i, "in", "schema"):
				_, next := roleList(st, i+2) // schema names, not roles
				i = next
			case kw(st, i, "grant"), kw(st, i, "revoke"):
				return append(out, grantRoles(st[i:])...)
			default:
				return out
			}
		}
		return out
	case kw(st, 0, "create", "policy"), kw(st, 0, "alter", "policy"):
		if find(st, 2, "rename") >= 0 {
			return nil
		}
		if i := find(st, 2, "to"); i >= 0 {
			names, _ := roleList(st, i+1)
			return names
		}
	case kw(st, 0, "set", "session", "authorization"):
		if len(st) > 3 && (st[3].kind == tString || st[3].kind == tQuoted || (st[3].kind == tWord && st[3].text != "default")) {
			return []string{st[3].text}
		}
	case kw(st, 0, "set", "role"):
		if len(st) > 2 && (st[2].kind == tString || st[2].kind == tQuoted || (st[2].kind == tWord && st[2].text != "none")) {
			return []string{st[2].text}
		}
	}
	return nil
}

// grantRoles reads GRANT ... TO roles and REVOKE ... FROM roles, with
// GRANTED BY. Without ON, it grants roles to roles: both sides count.
func grantRoles(st []token) []string {
	sep := "to"
	if kw(st, 0, "revoke") {
		sep = "from"
	}
	i := find(st, 1, sep)
	if i < 0 {
		return nil
	}
	out, _ := roleList(st, i+1)
	if on := find(st, 1, "on"); on < 0 || on > i {
		start := 1
		if kw(st, 0, "revoke") {
			switch {
			case kw(st, 1, "admin", "option", "for"), kw(st, 1, "inherit", "option", "for"), kw(st, 1, "set", "option", "for"):
				start = 4
			case kw(st, 1, "grant", "option", "for"):
				start = 4
			}
		}
		granted, _ := roleList(st, start)
		out = append(granted, out...)
	}
	return append(out, grantedBy(st, i+1)...)
}

// --- creating ---------------------------------------------------------------

// NewPrefix starts each line CreateScript prints for a role it created,
// followed by the role name in hex.
const NewPrefix = "HANGAR-NEW "

// literal quotes s as a SQL string literal (standard_conforming_strings).
func literal(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// CreateScript is a psql script that creates, in one transaction, each of
// names that does not exist yet, as a role that cannot log in and has no
// password. Existing roles are not touched. For each role it creates it
// prints NewPrefix and the name in hex.
func CreateScript(names []string) (string, error) {
	if len(names) == 0 {
		return "", nil
	}
	lits := make([]string, 0, len(names))
	for _, n := range names {
		if n == "" || strings.ContainsRune(n, 0) || len(n) > 63 {
			return "", fmt.Errorf("invalid role name %q", n)
		}
		lits = append(lits, literal(n))
	}
	missing := "FROM unnest(ARRAY[" + strings.Join(lits, ", ") + "]::text[]) AS r(name) " +
		"WHERE NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = r.name)"
	return "SET standard_conforming_strings = on;\n" +
		"BEGIN;\n" +
		"SELECT " + literal(NewPrefix) + " || encode(convert_to(r.name, 'UTF8'), 'hex') " + missing + ";\n" +
		"SELECT format('CREATE ROLE %I NOLOGIN', r.name) " + missing + " \\gexec\n" +
		"COMMIT;\n", nil
}

// ParseCreated reads the names CreateScript reported as created.
func ParseCreated(out string) []string {
	var names []string
	for line := range strings.SplitSeq(out, "\n") {
		h, ok := strings.CutPrefix(strings.TrimSpace(line), strings.TrimSpace(NewPrefix))
		if !ok {
			continue
		}
		if b, err := hex.DecodeString(strings.TrimSpace(h)); err == nil && len(b) > 0 {
			names = append(names, string(b))
		}
	}
	return names
}
