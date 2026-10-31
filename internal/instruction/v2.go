package instruction

import (
	"regexp"
	"time"
)

const Version2 = "tool-instructions-v2"

// A bounded syntax signal for directives that target the assistant's answer.
// It cannot determine whether a directive is malicious, quoted or legitimate.
var answerManipulation = regexp.MustCompile(`(?i)\b(?:include|insert|add|append|place|put)\b[^\n.!?。！？]{0,160}\b(?:in|into|to)\s+(?:your|the)\s+(?:final\s+)?(?:answer|reply|response|output)\b|\b(?:output|say|print|return)\s+(?:only|exactly)\b|(?:在|向)(?:你的|您的|最终|最后|的)*(?:回答|回复|答复|输出)(?:中|里)?[^\n。！？]{0,40}(?:加入|添加|插入|包含|附上)|(?:只|仅)(?:输出|回答|回复)`)

func SupportedVersion(version string) bool { return version == Version || version == Version2 }

func SupportedRule(version, rule string) bool {
	if !SupportedVersion(version) {
		return false
	}
	return rule == "task_override" || rule == "authority_spoof" || rule == "role_delimiter" || version == Version2 && rule == "answer_manipulation"
}

func DetectVersion(version, text string) (r Result) {
	start := time.Now()
	defer func() { r.DurationUS = time.Since(start).Microseconds() }()
	if !SupportedVersion(version) {
		return Result{State: "unknown", RuleIDs: []string{}}
	}
	r = Detect(text)
	if version == Version2 && r.State != "unknown" && answerManipulation.MatchString(text) {
		r.State = "observed"
		r.RuleIDs = append(r.RuleIDs, "answer_manipulation")
	}
	return r
}
