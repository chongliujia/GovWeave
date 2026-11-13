package sensitive

type Descriptor struct {
	ID          string   `json:"id"`
	Version     string   `json:"version"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Execution   string   `json:"execution"`
	Categories  []string `json:"categories"`
	Modes       []string `json:"modes"`
	MaxBytes    int      `json:"max_bytes"`
	MaxFindings int      `json:"max_findings"`
	Streaming   bool     `json:"streaming"`
}

type plugin struct {
	version     string
	description string
	scan        func([]byte) Result
}

var plugins = [...]plugin{
	{Version, "Literal credential, email and mainland China mobile patterns.", Detect},
	{Version2, "Adds bounded full-width, zero-width and bracketed email normalization.", detectNormalized},
	{Version3, "Adds paired email formatting and bounded single-layer Base64 detection.", detectV3},
}

func Catalog() []Descriptor {
	items := make([]Descriptor, 0, len(plugins))
	for _, registered := range plugins {
		items = append(items, Descriptor{
			ID: "sensitive-text", Version: registered.version, Name: "Sensitive text detector",
			Description: registered.description, Execution: "compiled_local",
			Categories: []string{"credential", "email", "phone"},
			Modes:      []string{"disabled", "observe", "block", "redact"},
			MaxBytes:   MaxBytes, MaxFindings: MaxFindings,
		})
	}
	return items
}

func Supports(version string) bool {
	for _, registered := range plugins {
		if registered.version == version {
			return true
		}
	}
	return false
}

func Scan(input []byte, version string) Result {
	for _, registered := range plugins {
		if registered.version == version {
			return registered.scan(input)
		}
	}
	return Result{DetectorVersion: version, State: "unknown", Reason: "unsupported_version", InputBytes: len(input), Findings: []Finding{}}
}
