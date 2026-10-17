// Package chaos holds the chaos tests of the security review: a real hangard
// process and the real Docker, with things going wrong on purpose — the
// panel killed in the middle of a deploy, containers stopped behind its
// back, Docker going away, the database locked, the disk full, a broken
// deploy log. They run with -tags integration (just test-integration);
// every project they create starts with "e2e-cx-" and is removed at the end.
package chaos
