package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeURL(t *testing.T) {
	valid := map[string]string{
		" https://AI.Example.com/ ": "https://ai.example.com",
		"http://10.0.0.20:8080":     "http://10.0.0.20:8080",
		"http://localhost:8080/":    "http://localhost:8080",
		"http://[::1]:8080":         "http://[::1]:8080",
		"https://gateway":           "https://gateway",
	}
	for input, want := range valid {
		t.Run(input, func(t *testing.T) {
			got, err := NormalizeURL(input)
			if err != nil || got != want {
				t.Fatalf("got %q, %v; want %q", got, err, want)
			}
		})
	}
	for _, input := range []string{"", "ai.example.com", "ftp://gateway", "//gateway", "https://name:password@gateway", "https://gateway/v1", "https://gateway/mcp", "https://gateway/prefix", "https://gateway?", "https://gateway#", "http://0.0.0.0:8080", "http://[::]:8080", "http://224.0.0.1", "http://gateway:0", "http://gateway:65536", "http://gateway:", "http://-gateway", "http://foo..bar", "http://gateway/%2f", "https://gate\nway", "https://gateway\\evil", "https://gate\"way", "http://[not-ip]", "https://gateway."} {
		t.Run("reject "+input, func(t *testing.T) {
			if _, err := NormalizeURL(input); err == nil {
				t.Fatalf("accepted invalid URL %q", input)
			}
		})
	}
}

func TestDeploymentPrecedenceAndStrictDecoding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deployment.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"public_url":"https://file.example.com/","organization_name":"File org"}`), 0600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"GOVWEAVE_PUBLIC_URL": "https://env.example.com", "GOVWEAVE_LISTEN_ADDR": "0.0.0.0:8081"}
	d, err := Load(path, func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if err != nil {
		t.Fatal(err)
	}
	if d.PublicURL != "https://env.example.com" || d.Sources["public_url"] != "environment" || d.Sources["organization_name"] != "file" || d.ListenAddr != "0.0.0.0:8081" {
		t.Fatalf("incorrect precedence: %+v", d)
	}
	for _, content := range []string{`{"schema_version":1,"typo":true}`, `{"schema_version":2}`, `{"listen_addr":"127.0.0.1:8080"}`, `{"schema_version":1} {}`, `null`, `{"schema_version":1,"listen_addr":"127.0.0.1:0"}`, `{"schema_version":1,"data_dir":""}`, `{"schema_version":1,"public_url":null}`, `{"schema_version":1,"organization_name":""}`, `{"schema_version":1}` + strings.Repeat(" ", 65536)} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path, func(string) (string, bool) { return "", false }); err == nil {
			t.Fatalf("accepted %s", content)
		}
	}
}

func TestEmptyEnvironmentIsNotSilentFallback(t *testing.T) {
	_, err := Load("", func(k string) (string, bool) { return "", k == "GOVWEAVE_PUBLIC_URL" })
	if err == nil {
		t.Fatal("empty public URL environment value must fail")
	}
}

func TestNameValidation(t *testing.T) {
	name, err := NormalizeName("  企业 AI 平台  ")
	if err != nil || name != "企业 AI 平台" {
		t.Fatalf("%q %v", name, err)
	}
	for _, input := range []string{"", "  ", "hello\nworld", strings.Repeat("名", 101)} {
		if _, err := NormalizeName(input); err == nil {
			t.Fatal("accepted invalid name")
		}
	}
}
