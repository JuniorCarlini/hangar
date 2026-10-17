package deps

import (
	"math"
	"strings"
)

// Severity of an advisory, from OSV's data.
const (
	SevCritical = "critical"
	SevHigh     = "high"
	SevMedium   = "medium"
	SevLow      = "low"
	SevUnknown  = "unknown"
	SevNone     = "none" // tag updates: no advisory
)

// Levels of a finding (docs/14): how loud the warning is.
const (
	LevelCritical = "critical" // 🔴 critical/high CVE with a fix: warn now
	LevelSecurity = "security" // 🟠 other CVEs: daily summary
	LevelMinor    = "minor"    // 🟡 patch/minor update: weekly summary
	LevelMajor    = "major"    // ⚪ major update (may break): weekly, separate
)

// Levels lists the levels from the loudest.
var Levels = []string{LevelCritical, LevelSecurity, LevelMinor, LevelMajor}

// vulnLevel is the level of a vulnerability: critical only when it is
// critical or high AND a fixed version exists (there is something to do
// right now). Everything else waits for the daily summary.
func vulnLevel(severity, fixed string) string {
	if (severity == SevCritical || severity == SevHigh) && fixed != "" {
		return LevelCritical
	}
	return LevelSecurity
}

// severityOf reads an OSV record's severity: the database's own rating
// (GitHub's "CRITICAL", "HIGH", "MODERATE", "LOW") first, then the highest
// CVSS score among the record's vectors.
func severityOf(v osvVuln) string {
	if s := ratingWord(v.DatabaseSpecific.Severity); s != "" {
		return s
	}
	for _, a := range v.Affected {
		if s := ratingWord(a.EcosystemSpecific.Severity); s != "" {
			return s
		}
		if s := ratingWord(a.DatabaseSpecific.Severity); s != "" {
			return s
		}
	}
	best := -1.0
	for _, s := range v.Severity {
		var score float64
		switch s.Type {
		case "CVSS_V3":
			score = cvss3Score(s.Score)
		case "CVSS_V4":
			score = cvss4Estimate(s.Score)
		default:
			continue
		}
		best = math.Max(best, score)
	}
	if best < 0 {
		return SevUnknown
	}
	return scoreWord(best)
}

func ratingWord(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SevCritical
	case "high", "important":
		return SevHigh
	case "moderate", "medium":
		return SevMedium
	case "low", "negligible", "unimportant":
		return SevLow
	}
	return ""
}

func scoreWord(score float64) string {
	switch {
	case score >= 9:
		return SevCritical
	case score >= 7:
		return SevHigh
	case score >= 4:
		return SevMedium
	case score > 0:
		return SevLow
	}
	return SevUnknown
}

func vectorMetrics(vector string) map[string]string {
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/") {
		if k, v, ok := strings.Cut(part, ":"); ok {
			m[k] = v
		}
	}
	return m
}

// cvss3Score is the CVSS v3.x base score of a vector
// ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" → 9.8); -1 when the
// vector is not valid.
func cvss3Score(vector string) float64 {
	if !strings.HasPrefix(vector, "CVSS:3.") {
		return -1
	}
	m := vectorMetrics(vector)
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	c, okC := cia[m["C"]]
	i, okI := cia[m["I"]]
	a, okA := cia[m["A"]]
	changed := m["S"] == "C"
	var pr float64
	switch m["PR"] {
	case "N":
		pr = 0.85
	case "L":
		pr = 0.62
		if changed {
			pr = 0.68
		}
	case "H":
		pr = 0.27
		if changed {
			pr = 0.5
		}
	}
	if av == 0 || ac == 0 || ui == 0 || pr == 0 || !okC || !okI || !okA || (m["S"] != "U" && !changed) {
		return -1
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0
	}
	exploit := 8.22 * av * ac * pr * ui
	if changed {
		return roundUp(math.Min(1.08*(impact+exploit), 10))
	}
	return roundUp(math.Min(impact+exploit, 10))
}

// roundUp is CVSS's "round up to one decimal".
func roundUp(x float64) float64 {
	i := math.Round(x * 100000)
	if math.Mod(i, 10000) == 0 {
		return i / 100000
	}
	return (math.Floor(i/10000) + 1) / 10
}

// cvss4Estimate approximates a CVSS v4 base score. The exact v4 formula is a
// large lookup table; for a warning level it is enough to know whether a
// network-reachable flaw hits confidentiality, integrity or availability
// hard, which is what this estimate looks at.
func cvss4Estimate(vector string) float64 {
	if !strings.HasPrefix(vector, "CVSS:4.") {
		return -1
	}
	m := vectorMetrics(vector)
	high := 0
	for _, k := range []string{"VC", "VI", "VA"} {
		if m[k] == "H" {
			high++
		}
	}
	low := 0
	for _, k := range []string{"VC", "VI", "VA", "SC", "SI", "SA"} {
		if m[k] == "L" {
			low++
		}
	}
	easy := m["AV"] == "N" && m["AC"] == "L" && m["AT"] == "N" && m["PR"] == "N"
	switch {
	case high >= 2 && easy && m["UI"] == "N":
		return 9.3
	case high >= 1 && (m["AV"] == "N" || m["AV"] == "A"):
		return 7.5
	case high >= 1 || low >= 2:
		return 5.5
	case low >= 1:
		return 2.5
	}
	return 0
}
