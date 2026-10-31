package leakage

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const v2MaxDepth = 2
const v2MaxCandidates = 256
const v2MaxNodes = 128
const v2MaxDecodedBytes = 64 << 10
const v2MaxScannedBytes = 64 << 10

var decimalPattern = regexp.MustCompile(`(?:[0-9]{2,3}[ \t\r\n,;:-]+){19,}[0-9]{2,3}`)
var chunkPattern = regexp.MustCompile(`[A-Za-z0-9+/_-]{2,}={0,2}`)

func SupportedVersion(version string) bool { return version == VersionV1 || version == Version }

func DetectVersion(version, marker string, text []byte) (Result, error) {
	switch version {
	case VersionV1:
		return DetectV1(marker, text), nil
	case Version:
		return Detect(marker, text), nil
	default:
		return Result{}, errors.New("unsupported canary detector version")
	}
}

type scanNode struct {
	text       string
	path       []string
	start, end int
	scope      string
}

type boundedSearch struct {
	marker, key                string
	result                     Result
	queue                      []scanNode
	seen                       map[string]bool
	attempts, decoded, scanned int
	limited, exhausted         bool
}

func (s *boundedSearch) match(node scanNode) bool {
	at := strings.Index(node.text, s.marker)
	normalized := false
	var starts, ends []int
	if at < 0 {
		var value string
		value, starts, ends = normalize(node.text)
		at = strings.Index(value, s.key)
		normalized = true
	}
	if at < 0 {
		return false
	}
	match := Match{StartByte: node.start, EndByte: node.end, SpanScope: node.scope}
	if len(node.path) == 0 {
		if normalized {
			match.Representation = "normalized"
			match.StartByte = starts[at]
			match.EndByte = ends[at+len(s.key)-1]
		} else {
			match.Representation = "exact"
			match.StartByte = at
			match.EndByte = at + len(s.marker)
		}
	} else {
		match.Representation = node.path[0]
		if len(node.path) > 1 {
			match.Representation = "composed"
			match.Transformations = append([]string{}, node.path...)
		}
		match.Normalized = normalized
	}
	s.result.State, s.result.Reason = "observed", "full_marker_observed"
	s.result.Matches = []Match{match}
	return true
}

func (s *boundedSearch) add(parent scanNode, method, decoded string, start, end int, scope string) bool {
	if !utf8.ValidString(decoded) || decoded == parent.text || s.seen[decoded] {
		return false
	}
	if len(s.queue) >= v2MaxNodes || s.decoded+len(decoded) > v2MaxDecodedBytes {
		s.exhausted = true
		return false
	}
	path := append(append([]string{}, parent.path...), method)
	node := scanNode{text: decoded, path: path, start: start, end: end, scope: scope}
	if len(parent.path) > 0 {
		node.start, node.end, node.scope = parent.start, parent.end, parent.scope
	}
	s.decoded += len(decoded)
	s.seen[decoded] = true
	if s.match(node) {
		return true
	}
	s.queue = append(s.queue, node)
	return false
}

func (s *boundedSearch) admit(size int) bool {
	s.attempts++
	if s.attempts > v2MaxCandidates {
		s.exhausted = true
		return false
	}
	if size > maxCandidateBytes {
		s.limited = true
		return false
	}
	return true
}

func decodeBase64(value string) (string, bool) {
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		decoded, err := encoding.DecodeString(value)
		if err == nil && utf8.Valid(decoded) {
			return string(decoded), true
		}
	}
	return "", false
}

func decodeDecimal(value string) (string, bool) {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ',' || r == ';' || r == ':' || r == '-'
	})
	output := make([]byte, 0, len(parts))
	for _, part := range parts {
		v, err := strconv.Atoi(part)
		if err != nil || v < 0 || v > 127 {
			return "", false
		}
		output = append(output, byte(v))
	}
	return string(output), len(output) >= 20
}

func rot13(value string) string {
	data := []byte(value)
	for i, c := range data {
		if c >= 'a' && c <= 'z' {
			data[i] = 'a' + (c-'a'+13)%26
		} else if c >= 'A' && c <= 'Z' {
			data[i] = 'A' + (c-'A'+13)%26
		}
	}
	return string(data)
}

func reverse(value string) string {
	runes := []rune(value)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func printableASCII(value string) bool {
	if len(value) == 0 {
		return false
	}
	for _, c := range []byte(value) {
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}

func whitespace(value string) bool {
	if len(value) == 0 {
		return false
	}
	for _, c := range value {
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			return false
		}
	}
	return true
}

func base64Byte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("+/_-=", rune(c))
}

// Only contiguous whitespace-separated valid printable chunks are joined.
// Prose, punctuation, missing/invalid chunks and oversized tokens break runs.
func (s *boundedSearch) chunks(node scanNode) bool {
	start, end, count := 0, 0, 0
	var decoded strings.Builder
	flush := func() bool {
		if count >= 2 && s.admit(end-start) {
			return s.add(node, "base64_chunks", decoded.String(), start, end, "encoded_candidate")
		}
		return false
	}
	for _, span := range chunkPattern.FindAllStringIndex(node.text, -1) {
		left, right := span[0], span[1]
		if right-left > maxCandidateBytes {
			if flush() {
				return true
			}
			s.limited = true
			count = 0
			decoded.Reset()
			continue
		}
		validBoundary := (left == 0 || !base64Byte(node.text[left-1])) && (right == len(node.text) || !base64Byte(node.text[right]))
		value, ok := decodeBase64(node.text[left:right])
		if !validBoundary || !ok || !printableASCII(value) {
			if flush() {
				return true
			}
			count = 0
			decoded.Reset()
			if s.exhausted {
				return false
			}
			continue
		}
		if count > 0 && !whitespace(node.text[end:left]) {
			if flush() {
				return true
			}
			count = 0
			decoded.Reset()
		}
		if s.exhausted {
			return false
		}
		if count == 0 {
			start = left
		}
		if decoded.Len()+len(value) > maxCandidateBytes {
			s.limited = true
			count = 0
			decoded.Reset()
			continue
		}
		decoded.WriteString(value)
		end = right
		count++
	}
	return flush()
}

func (s *boundedSearch) expand(node scanNode) bool {
	transforms := []struct {
		name      string
		pattern   *regexp.Regexp
		qualifies func(string) bool
		decode    func(string) (string, bool)
	}{
		{"percent", percentPattern, func(v string) bool { return strings.Contains(v, "%") }, func(v string) (string, bool) { out, err := url.PathUnescape(v); return out, err == nil }},
		{"json_escape", escapedPattern, func(v string) bool { return strings.Contains(v, `\u`) }, func(v string) (string, bool) {
			var out string
			err := json.Unmarshal([]byte(`"`+v+`"`), &out)
			return out, err == nil
		}},
		{"hex", hexPattern, nil, func(v string) (string, bool) { out, err := hex.DecodeString(v); return string(out), err == nil }},
		{"base64", base64Pattern, nil, decodeBase64},
		{"decimal", decimalPattern, nil, decodeDecimal},
	}
	for _, transform := range transforms {
		for _, span := range transform.pattern.FindAllStringIndex(node.text, -1) {
			candidate := node.text[span[0]:span[1]]
			if transform.qualifies != nil && !transform.qualifies(candidate) {
				continue
			}
			if !s.admit(len(candidate)) {
				if s.exhausted {
					return false
				}
				continue
			}
			if decoded, ok := transform.decode(candidate); ok && s.add(node, transform.name, decoded, span[0], span[1], "encoded_candidate") {
				return true
			}
			if s.exhausted {
				return false
			}
		}
	}
	if s.chunks(node) {
		return true
	}
	if s.exhausted {
		return false
	}
	for _, transform := range []struct {
		name  string
		apply func(string) string
	}{{"reversed", reverse}, {"rot13", rot13}} {
		if s.add(node, transform.name, transform.apply(node.text), 0, len(node.text), "transformed_region") {
			return true
		}
		if s.exhausted {
			return false
		}
	}
	return false
}

// Detect searches at most two reversible layers. Encoding candidates are never
// lowercased or separator-stripped before decoding. Normalization is terminal.
func Detect(marker string, text []byte) Result {
	return detectDepth(marker, text, v2MaxDepth)
}

func detectDepth(marker string, text []byte, maxDepth int) Result {
	result := Result{Version: Version, State: "unknown", InputBytes: len(text), Matches: []Match{}}
	if problem := InputProblem(marker, text); problem != "" {
		result.Reason = problem
		return result
	}
	result.MarkerSHA256 = MarkerDigest(marker)
	result.ScannedBytes = len(text)
	key, _, _ := normalize(marker)
	root := scanNode{text: string(text), end: len(text), scope: "raw_fragment"}
	search := boundedSearch{marker: marker, key: key, result: result, queue: []scanNode{root}, seen: map[string]bool{root.text: true}}
	if search.match(root) {
		return search.result
	}
	for i := 0; i < len(search.queue); i++ {
		node := search.queue[i]
		if len(node.path) >= maxDepth {
			continue
		}
		if search.scanned+len(node.text) > v2MaxScannedBytes {
			search.exhausted = true
			break
		}
		search.scanned += len(node.text)
		if search.expand(node) {
			return search.result
		}
		if search.exhausted {
			break
		}
	}
	if search.exhausted {
		search.result.Reason = "scan_budget_exceeded"
	} else if search.limited {
		search.result.Reason = "encoded_candidate_limit"
	} else {
		search.result.State, search.result.Reason = "not_observed", "full_marker_not_observed"
	}
	return search.result
}
