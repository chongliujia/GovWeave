// Package sensitive identifies a bounded set of credential and contact-data
// patterns. Findings describe text syntax/context, not ownership, validity of
// credentials, permission to disclose, or a legal conclusion.
package sensitive

import (
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const Version = "sensitive-text-v1"
const MaxBytes = 8192
const MaxFindings = 32

type Finding struct {
	Category  string `json:"category"`
	RuleID    string `json:"rule_id"`
	StartByte int    `json:"start_byte"`
	EndByte   int    `json:"end_byte"`
}

// Result contains only bounded metadata. In particular it contains neither
// matched values, input excerpts, normalized text, nor hashes of input text.
type Result struct {
	DetectorVersion string    `json:"detector_version"`
	State           string    `json:"state"`
	Reason          string    `json:"reason"`
	Findings        []Finding `json:"findings"`
	Truncated       bool      `json:"truncated"`
	InputBytes      int       `json:"input_bytes"`
	DurationUS      int64     `json:"duration_us"`
}

// These are deliberately the same credential patterns as credentials-v1.
// They are not online credential validators, and their known matching limits
// remain visible rather than silently changing an existing rule generation.
var credentialPatterns = []struct {
	id      string
	pattern *regexp.Regexp
}{
	{"private_key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----`)},
	{"api_key", regexp.MustCompile(`\b(?:sk-[A-Za-z0-9_-]{20,}|gw_app_[A-Za-z0-9_-]{43}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|AKIA[A-Z0-9]{16}\b)`)},
}

var emailCandidate = regexp.MustCompile("[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)+")
var mobileCandidate = regexp.MustCompile(`(?:\+86[ -]?)?1[3-9][0-9](?:[ -]?[0-9]{4}){2}`)
var englishPhoneContext = regexp.MustCompile(`(?i)\b(?:phone|mobile|tel|telephone)\b`)

// Detect scans one UTF-8 text with a fixed, local rule set. Not-observed only
// means these patterns were not found. Unknown means the scan could not cover
// the input within the supported limits; callers must not treat it as clean.
func Detect(input []byte) (result Result) {
	started := time.Now()
	result = Result{DetectorVersion: Version, State: "unknown", Reason: "input_limit", Findings: []Finding{}, InputBytes: len(input)}
	defer func() { result.DurationUS = time.Since(started).Microseconds() }()
	if len(input) > MaxBytes {
		return result
	}
	if !utf8.Valid(input) {
		result.Reason = "invalid_utf8"
		return result
	}
	text := string(input)
	// At most 33 accepted findings from each rule are needed to determine
	// overflow and the globally earliest 32 spans. Candidate scanning itself
	// is bounded by the 8192-byte input limit and Go's RE2 implementation.
	findings := make([]Finding, 0, 4*(MaxFindings+1))
	for _, rule := range credentialPatterns {
		for _, span := range rule.pattern.FindAllStringIndex(text, MaxFindings+1) {
			findings = append(findings, Finding{Category: "credential", RuleID: rule.id, StartByte: span[0], EndByte: span[1]})
		}
	}
	emails := 0
	for _, span := range emailCandidate.FindAllStringIndex(text, -1) {
		if !validEmail(text, span[0], span[1]) {
			continue
		}
		findings = append(findings, Finding{Category: "email", RuleID: "email_address", StartByte: span[0], EndByte: span[1]})
		emails++
		if emails > MaxFindings {
			break
		}
	}
	phones := 0
	for _, span := range mobileCandidate.FindAllStringIndex(text, -1) {
		if !validMobile(text, span[0], span[1]) || overlapsOtherFinding(findings, span[0], span[1]) {
			continue
		}
		findings = append(findings, Finding{Category: "phone", RuleID: "cn_mobile_phone", StartByte: span[0], EndByte: span[1]})
		phones++
		if phones > MaxFindings {
			break
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.StartByte != b.StartByte {
			return a.StartByte < b.StartByte
		}
		if a.EndByte != b.EndByte {
			return a.EndByte < b.EndByte
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		return a.RuleID < b.RuleID
	})
	for _, finding := range findings {
		if len(result.Findings) != 0 && result.Findings[len(result.Findings)-1] == finding {
			continue
		}
		if len(result.Findings) == MaxFindings {
			result.Reason, result.Truncated = "finding_limit", true
			return result
		}
		result.Findings = append(result.Findings, finding)
	}
	result.State, result.Reason = "not_observed", "patterns_not_observed"
	if len(result.Findings) > 0 {
		result.State, result.Reason = "observed", "patterns_observed"
	}
	return result
}

func asciiLetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func asciiDigit(c byte) bool { return c >= '0' && c <= '9' }

func localEmailByte(c byte) bool {
	return asciiLetter(c) || asciiDigit(c) || strings.ContainsRune(".!#$%&'*+/=?^_`{|}~-", rune(c))
}

// This is an intentionally limited ASCII address recognizer, not an RFC 5322
// parser or a mail deliverability check. Quoted/Unicode locals and IP-literal
// domains are unsupported. A domain must have at least two labels and an
// alphabetic final label of at least two characters.
func validEmail(text string, start, end int) bool {
	value := text[start:end]
	if len(value) > 254 {
		return false
	}
	at := strings.IndexByte(value, '@')
	local, domain := value[:at], value[at+1:]
	if len(local) > 64 || local[0] == '.' || local[len(local)-1] == '.' || strings.Contains(local, "..") {
		return false
	}
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	tld := labels[len(labels)-1]
	if len(tld) < 2 {
		return false
	}
	for i := range tld {
		if !asciiLetter(tld[i]) {
			return false
		}
	}
	if start > 0 {
		previous, _ := utf8.DecodeLastRuneInString(text[:start])
		if unicode.IsLetter(previous) || unicode.IsDigit(previous) || previous == '@' || previous < utf8.RuneSelf && localEmailByte(byte(previous)) {
			return false
		}
	}
	if end < len(text) {
		next, _ := utf8.DecodeRuneInString(text[end:])
		if unicode.IsLetter(next) || unicode.IsDigit(next) || strings.ContainsRune("_@-", next) {
			return false
		}
		// A sentence-ending period is punctuation. A following domain-like
		// segment or doubled period means this was only a partial candidate.
		if next == '.' && end+1 < len(text) {
			after, _ := utf8.DecodeRuneInString(text[end+1:])
			if unicode.IsLetter(after) || unicode.IsDigit(after) || strings.ContainsRune("._@-", after) {
				return false
			}
		}
	}
	return true
}

func phoneBoundary(r rune) bool {
	return unicode.IsDigit(r) || r < utf8.RuneSelf && (asciiLetter(byte(r)) || strings.ContainsRune("_.+/@", r))
}

func validMobile(text string, start, end int) bool {
	if start > 0 {
		previous, _ := utf8.DecodeLastRuneInString(text[:start])
		if phoneBoundary(previous) {
			return false
		}
		if previous == '-' && start > 1 {
			before, _ := utf8.DecodeLastRuneInString(text[:start-1])
			if unicode.IsLetter(before) || unicode.IsDigit(before) || before == '_' {
				return false
			}
		}
	}
	if end < len(text) {
		next, _ := utf8.DecodeRuneInString(text[end:])
		if phoneBoundary(next) {
			return false
		}
		// Do not accept an initial 11-digit part of a longer hyphenated ID.
		if next == '-' && end+1 < len(text) {
			after := text[end+1]
			if asciiDigit(after) || asciiLetter(after) || after == '_' {
				return false
			}
		}
	}
	if strings.HasPrefix(text[start:end], "+86") {
		return true
	}
	left, right := start, end
	for count := 0; count < 24 && left > 0; count++ {
		_, size := utf8.DecodeLastRuneInString(text[:left])
		left -= size
	}
	for count := 0; count < 24 && right < len(text); count++ {
		_, size := utf8.DecodeRuneInString(text[right:])
		right += size
	}
	context := text[left:start] + " " + text[end:right]
	if englishPhoneContext.MatchString(context) {
		return true
	}
	for _, label := range []string{"手机", "手机号", "电话", "联系"} {
		if strings.Contains(context, label) {
			return true
		}
	}
	return false
}

func overlapsOtherFinding(findings []Finding, start, end int) bool {
	for _, finding := range findings {
		if finding.Category != "phone" && start < finding.EndByte && end > finding.StartByte {
			return true
		}
	}
	return false
}
