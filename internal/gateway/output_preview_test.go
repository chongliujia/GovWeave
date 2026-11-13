package gateway

import (
	"encoding/base64"
	"reflect"
	"slices"
	"strings"
	"testing"

	"govweave/internal/sensitive"
)

func TestSensitiveOutputPreviewModes(t *testing.T) {
	text := "Contact private@example.test"
	for _, mode := range []string{"disabled", "observe", "block", "redact"} {
		t.Run(mode, func(t *testing.T) {
			preview, err := PreviewSensitiveOutput(OutputPreviewInput{Text: text, DetectorVersion: sensitive.Version3, Mode: mode, Categories: []string{"email"}})
			if err != nil || !preview.PreviewOnly || preview.Mode != mode || preview.DetectorVersion != sensitive.Version3 {
				t.Fatal(preview, err)
			}
			switch mode {
			case "disabled":
				if preview.State != "not_evaluated" || preview.Result != "disabled" || len(preview.MatchedRules) != 0 || preview.Output == nil || *preview.Output != text {
					t.Fatal(preview)
				}
			case "observe":
				if preview.Result != "observe" || preview.Output == nil || *preview.Output != text {
					t.Fatal(preview)
				}
			case "block":
				if preview.Result != "block" || preview.Output != nil {
					t.Fatal(preview)
				}
			case "redact":
				if preview.Result != "redacted" || preview.Output == nil || *preview.Output != "Contact [REDACTED]" || preview.Redaction == nil || preview.Redaction.Replacements != 1 {
					t.Fatal(preview)
				}
			}
		})
	}
}

func TestSensitiveOutputPreviewVersionsAndExceptions(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("private@example.test"))
	for _, test := range []struct {
		version, text, expected string
		categories, exceptions  []string
		exempted                int
	}{
		{sensitive.Version, "private [at] example [dot] test", "private [at] example [dot] test", []string{"email"}, nil, 0},
		{sensitive.Version2, "private [at] example [dot] test", "[REDACTED]", []string{"email"}, nil, 0},
		{sensitive.Version3, encoded, "[REDACTED]", []string{"email"}, nil, 0},
		{sensitive.Version3, "**public@example.test**", "**public@example.test**", []string{"email"}, []string{"public@example.test"}, 1},
		{sensitive.Version3, encoded, "[REDACTED]", []string{"email"}, []string{"private@example.test"}, 0},
		{sensitive.Version3, "before -----BEGIN PRIVATE KEY----- after", "[REDACTED]", []string{"credential"}, nil, 0},
		{sensitive.Version3, "private@example.test", "private@example.test", []string{"phone"}, nil, 0},
		{sensitive.Version3, "<script>sample</script>", "<script>sample</script>", []string{"email"}, nil, 0},
		{sensitive.Version3, "plain sample", "plain sample", []string{"phone", "email", "credential"}, []string{"z@example.test", "a@example.test"}, 0},
	} {
		input := OutputPreviewInput{Text: test.text, DetectorVersion: test.version, Mode: "redact", Categories: test.categories, PublicEmails: test.exceptions}
		originalCategories, originalEmails := slices.Clone(input.Categories), slices.Clone(input.PublicEmails)
		preview, err := PreviewSensitiveOutput(input)
		if err != nil || preview.Output == nil || *preview.Output != test.expected || preview.PublicEmailExceptions != test.exempted {
			t.Fatalf("%s: %+v %v", test.version, preview, err)
		}
		if !reflect.DeepEqual(input.Categories, originalCategories) || !reflect.DeepEqual(input.PublicEmails, originalEmails) {
			t.Fatal("preview mutated draft slices")
		}
	}
}

func TestSensitiveOutputPreviewUnknownWithholdsOutput(t *testing.T) {
	for _, mode := range []string{"observe", "block", "redact"} {
		preview, err := PreviewSensitiveOutput(OutputPreviewInput{Text: strings.Repeat("private@example.test ", 33), DetectorVersion: sensitive.Version3, Mode: mode, Categories: []string{"email"}})
		if err != nil || preview.State != "unknown" || preview.Result != "error" || preview.Output != nil || preview.Redaction != nil {
			t.Fatalf("%s: %+v %v", mode, preview, err)
		}
	}
}

func TestSensitiveOutputPreviewValidation(t *testing.T) {
	valid := OutputPreviewInput{Text: "private@example.test", DetectorVersion: sensitive.Version3, Mode: "redact", Categories: []string{"email"}}
	for _, alter := range []func(*OutputPreviewInput){
		func(input *OutputPreviewInput) { input.Text = " " },
		func(input *OutputPreviewInput) { input.Text = strings.Repeat("a", sensitive.MaxBytes+1) },
		func(input *OutputPreviewInput) { input.Text = strings.Repeat("界", 2731) },
		func(input *OutputPreviewInput) { input.Text = string([]byte{0xff}) },
		func(input *OutputPreviewInput) { input.Text = "\ufffd" },
		func(input *OutputPreviewInput) { input.DetectorVersion = "latest" },
		func(input *OutputPreviewInput) { input.Mode = "allow" },
		func(input *OutputPreviewInput) { input.Categories = nil },
		func(input *OutputPreviewInput) { input.Categories = []string{"email", "email"} },
		func(input *OutputPreviewInput) { input.Categories = []string{"unknown"} },
		func(input *OutputPreviewInput) { input.PublicEmails = []string{"*@example.test"} },
		func(input *OutputPreviewInput) {
			input.PublicEmails = []string{"public@example.test", "public@example.test"}
		},
	} {
		input := valid
		alter(&input)
		if _, err := PreviewSensitiveOutput(input); err == nil {
			t.Fatal("invalid preview accepted")
		}
	}
	valid.Text = strings.Repeat(".", sensitive.MaxBytes)
	if _, err := PreviewSensitiveOutput(valid); err != nil {
		t.Fatal("valid byte limit rejected", err)
	}
}
