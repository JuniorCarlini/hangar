package projects

import (
	"net/url"
	"strings"
)

// A database made by hand (from the image, not a template) gets the same
// connection URL a template's would export (DATABASE_URL, MONGODB_URL,
// REDIS_URL), built from the variables its official image reads: the
// service that connects to it takes one value instead of five. Nothing is
// stored: like HOST and PORT, it is worked out when a reference is read,
// so it follows the variables when they change.

// dbKind is a database image family whose official image is configured by
// well-known variables.
type dbKind int

const (
	dbNone dbKind = iota
	dbPostgres
	dbMySQL
	dbMongo
	dbRedis
)

// dbKindOf recognizes the official images (and their usual variants, such
// as postgis/postgis or bitnami/redis) by the image's own name, without
// registry, namespace or tag.
func dbKindOf(image string) dbKind {
	name := image
	if i := strings.LastIndexByte(name, '@'); i >= 0 {
		name = name[:i]
	}
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	if i := strings.IndexByte(name, ':'); i >= 0 {
		name = name[:i]
	}
	switch name {
	case "postgres", "postgis", "pgvector", "timescaledb", "timescaledb-ha":
		return dbPostgres
	case "mysql", "mariadb", "percona-server":
		return dbMySQL
	case "mongo", "mongodb", "mongodb-community-server":
		return dbMongo
	case "redis", "redis-stack-server", "valkey", "keydb", "dragonfly":
		return dbRedis
	}
	return dbNone
}

// derivedURL is the connection URL of a hand-made database service: its
// key, the URL, and whether it holds a password. ok is false for anything
// else, or when a value it needs is itself a reference (the URL would have
// to escape text that is resolved later).
func derivedURL(image string, vals map[string]string, host, port string) (key, value string, secret, ok bool) {
	get := func(keys ...string) string {
		for _, k := range keys {
			if v := vals[k]; v != "" {
				return v
			}
		}
		return ""
	}
	withPort := func(def string) string {
		if port == "" {
			port = def
		}
		return host + ":" + port
	}
	build := func(scheme, user, pass, hostport, path, query string) (string, bool) {
		for _, s := range []string{user, pass, path} {
			if strings.Contains(s, "${{") {
				return "", false
			}
		}
		u := url.URL{Scheme: scheme, Host: hostport, Path: "/" + path, RawQuery: query}
		switch {
		case user != "" && pass != "":
			u.User = url.UserPassword(user, pass)
		case user != "":
			u.User = url.User(user)
		case pass != "":
			u.User = url.UserPassword("", pass)
		}
		return u.String(), true
	}

	switch dbKindOf(image) {
	case dbPostgres:
		user := get("POSTGRES_USER")
		if user == "" {
			user = "postgres"
		}
		db := get("POSTGRES_DB")
		if db == "" {
			db = user
		}
		pass := get("POSTGRES_PASSWORD")
		v, ok := build("postgres", user, pass, withPort("5432"), db, "")
		return "DATABASE_URL", v, pass != "", ok
	case dbMySQL:
		user, pass := get("MYSQL_USER", "MARIADB_USER"), get("MYSQL_PASSWORD", "MARIADB_PASSWORD")
		if user == "" {
			user, pass = "root", get("MYSQL_ROOT_PASSWORD", "MARIADB_ROOT_PASSWORD")
		}
		v, ok := build("mysql", user, pass, withPort("3306"), get("MYSQL_DATABASE", "MARIADB_DATABASE"), "")
		return "DATABASE_URL", v, pass != "", ok
	case dbMongo:
		user, pass := get("MONGO_INITDB_ROOT_USERNAME"), get("MONGO_INITDB_ROOT_PASSWORD")
		query := ""
		if user != "" {
			query = "authSource=admin"
		}
		v, ok := build("mongodb", user, pass, withPort("27017"), get("MONGO_INITDB_DATABASE"), query)
		return "MONGODB_URL", v, pass != "", ok
	case dbRedis:
		pass := get("REDIS_PASSWORD", "VALKEY_PASSWORD")
		v, ok := build("redis", "", pass, withPort("6379"), "0", "")
		return "REDIS_URL", v, pass != "", ok
	}
	return "", "", false, false
}
