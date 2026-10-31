// Package instruction checks untrusted retrieved text for explicit instruction
// override syntax. Absence of a match is not a prompt-injection safety verdict.
package instruction

import (
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const Version = "tool-instructions-v1"
const MaxBytes = 8192

type Result struct {
	State      string   `json:"state"`
	RuleIDs    []string `json:"rule_ids"`
	DurationUS int64    `json:"duration_us"`
}

// Quotation or a provider's claim of safety never suppresses a match. This is
// conservative, including for training documents that quote these phrases.
var rules = []struct {
	id      string
	pattern *regexp.Regexp
}{
	{"task_override", regexp.MustCompile(`(?i)\b(?:ignore|disregard|forget)\s+(?:(?:all|the|your|any|original|previous|prior|user|system|developer)\s+){1,5}(?:instructions?|tasks?|questions?|prompts?)\b|(?:忽略|无视|忘记)(?:之前|先前|原有|原始|用户|系统|开发者|所有|的){1,5}(?:指令|任务|问题|提示)`)},
	{"authority_spoof", regexp.MustCompile(`(?i)\b(?:admin|system|developer)\s+override\s*:|\bnew\s+(?:system|developer)\s+instructions?\s*:|(?:系统|管理员|开发者)(?:覆盖|覆写|新指令)[:：]`)},
	{"role_delimiter", regexp.MustCompile(`(?i)(?:<\|im_start\|>|<\|start_header_id\|>)\s*(?:system|developer)\b`)},
}

func Detect(text string) (r Result) {
	start := time.Now()
	r = Result{State: "unknown", RuleIDs: []string{}}
	defer func() { r.DurationUS = time.Since(start).Microseconds() }()
	if len(text) > MaxBytes || !utf8.ValidString(text) || strings.ContainsRune(text, utf8.RuneError) {
		return r
	}
	r.State = "not_observed"
	for _, rule := range rules {
		if rule.pattern.MatchString(text) {
			r.State = "observed"
			r.RuleIDs = append(r.RuleIDs, rule.id)
		}
	}
	return r
}
