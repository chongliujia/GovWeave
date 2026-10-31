package sensitive

import (
	"encoding/base64"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const Version3 = "sensitive-text-v3"
const MaxEncodedTokenBytes = 2048
const MaxEncodedViews = 32

// Supports and Scan are the extensible registry. The original DetectVersion
// and SupportedVersion stay byte-for-byte frozen with the v1/v2 implementation.
func Supports(version string) bool { return SupportedVersion(version) || version == Version3 }

func Scan(input []byte, version string) Result {
	if version == Version3 {
		return detectV3(input)
	}
	return DetectVersion(input, version)
}

// Recognize only whole ASCII addresses in paired inline code or strong-markup
// delimiters, with punctuation/space boundaries. This is not a Markdown parser.
// The finding covers the address bytes, never the delimiters. Transformed
// spellings and ambiguous/unpaired markup keep their historical observations.
func formattedEmails(text string, findings []Finding) []Finding {
	for _, delimiter := range []string{"**", "__", "`"} {
		for from := 0; from < len(text); {
			i := strings.Index(text[from:], delimiter)
			if i < 0 {
				break
			}
			start := from + i
			bodyStart := start + len(delimiter)
			j := strings.Index(text[bodyStart:], delimiter)
			if j < 0 {
				break
			}
			bodyEnd := bodyStart + j
			end := bodyEnd + len(delimiter)
			from = end
			if j < 3 || j > 254 || !formatBoundary(text, start, end) {
				continue
			}
			r := Detect([]byte(text[bodyStart:bodyEnd]))
			if r.State != "observed" || len(r.Findings) != 1 {
				continue
			}
			f := r.Findings[0]
			if f.Category != "email" || f.StartByte != 0 || f.EndByte != j {
				continue
			}
			kept := findings[:0]
			for _, previous := range findings {
				if previous.RuleID != "email_address" || previous.StartByte < start || previous.EndByte > end {
					kept = append(kept, previous)
				}
			}
			findings = append(kept, Finding{Category: "email", RuleID: "formatted_email_address", StartByte: bodyStart, EndByte: bodyEnd})
		}
	}
	return findings
}

func formatBoundary(text string, start, end int) bool {
	if start > 0 {
		r, _ := utf8.DecodeLastRuneInString(text[:start])
		if !unicode.IsSpace(r) && !strings.ContainsRune("([{<:;,!?，。；：（【", r) {
			return false
		}
	}
	if end < len(text) {
		r, n := utf8.DecodeRuneInString(text[end:])
		if !unicode.IsSpace(r) && !strings.ContainsRune(")]}>,;:.!?。，；：）】", r) {
			return false
		}
		if r == '.' && end+n < len(text) {
			next, _ := utf8.DecodeRuneInString(text[end+n:])
			if unicode.IsLetter(next) || unicode.IsDigit(next) || strings.ContainsRune("._@-", next) {
				return false
			}
		}
	}
	return true
}

func encodedByte(b byte) bool {
	return asciiLetter(b) || asciiDigit(b) || strings.ContainsRune("+/_-=", rune(b))
}

func decodeToken(token string) ([]byte, bool) {
	for _, codec := range []*base64.Encoding{base64.StdEncoding.Strict(), base64.RawStdEncoding.Strict(), base64.URLEncoding.Strict(), base64.RawURLEncoding.Strict()} {
		decoded, err := codec.DecodeString(token)
		if err != nil || codec.EncodeToString(decoded) != token || !utf8.Valid(decoded) {
			continue
		}
		if strings.ContainsFunc(string(decoded), func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' }) {
			return nil, false
		}
		return decoded, true
	}
	return nil, false
}

func detectV3(input []byte) (result Result) {
	started := time.Now()
	result = detectNormalized(input)
	result.DetectorVersion = Version3
	defer func() { result.DurationUS = time.Since(started).Microseconds() }()
	if result.State == "unknown" {
		return result
	}
	text := string(input)
	findings := formattedEmails(text, result.Findings)
	unknownReason := ""
	views := 0
	for start := 0; start < len(text); {
		if !encodedByte(text[start]) {
			start++
			continue
		}
		end := start + 1
		for end < len(text) && encodedByte(text[end]) {
			end++
		}
		tokenStart := start
		start = end
		if end-tokenStart < 8 {
			continue
		}
		if end-tokenStart > MaxEncodedTokenBytes {
			unknownReason = "encoding_limit"
			break
		}
		decoded, ok := decodeToken(text[tokenStart:end])
		if !ok {
			continue
		}
		views++
		if views > MaxEncodedViews {
			unknownReason = "encoding_limit"
			break
		}
		// Exactly one decoding layer. Scan normalized plaintext, without calling
		// Scan recursively. Every decoded finding maps to the whole source token.
		r := detectNormalized(decoded)
		if r.State == "unknown" {
			unknownReason = r.Reason
		}
		for _, f := range formattedEmails(string(decoded), r.Findings) {
			f.RuleID = "base64_" + f.RuleID
			f.StartByte, f.EndByte = tokenStart, end
			findings = append(findings, f)
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
		return a.RuleID < b.RuleID
	})
	result.Findings = []Finding{}
	for _, f := range findings {
		if len(result.Findings) > 0 && result.Findings[len(result.Findings)-1] == f {
			continue
		}
		if len(result.Findings) == MaxFindings {
			unknownReason = "finding_limit"
			break
		}
		result.Findings = append(result.Findings, f)
	}
	if unknownReason != "" {
		result.State, result.Reason, result.Truncated = "unknown", unknownReason, true
		return result
	}
	result.State, result.Reason = "not_observed", "patterns_not_observed"
	if len(result.Findings) > 0 {
		result.State, result.Reason = "observed", "patterns_observed"
	}
	return result
}
