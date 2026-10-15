// Package config validates deployment and browser configuration through the same rules.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const SchemaVersion = 1

type Deployment struct {
	SchemaVersion    int               `json:"schema_version"`
	ListenAddr       string            `json:"listen_addr,omitempty"`
	DataDir          string            `json:"data_dir,omitempty"`
	AdminTokenFile   string            `json:"admin_token_file,omitempty"`
	OrganizationName string            `json:"organization_name,omitempty"`
	PublicURL        string            `json:"public_url,omitempty"`
	Sources          map[string]string `json:"-"`
}

type Settings struct {
	OrganizationName string `json:"organization_name"`
	PublicURL        string `json:"public_url"`
}

// DecodeStrict also rejects trailing JSON, so one request cannot conceal a second object.
func DecodeStrict(r io.Reader, dst any) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err != nil {
			return err
		}
		return errors.New("expected exactly one JSON object")
	}
	return nil
}

func Load(path string, lookup func(string) (string, bool)) (Deployment, error) {
	d := Deployment{ListenAddr: "127.0.0.1:8080", DataDir: "./data", Sources: map[string]string{}}
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return d, fmt.Errorf("open deployment config: %w", err)
		}
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, 65537))
		if err != nil || len(data) > 65536 {
			return d, errors.New("deployment config must be readable and no larger than 64 KiB")
		}
		var fields map[string]json.RawMessage
		if err := DecodeStrict(bytes.NewReader(data), &fields); err != nil || fields == nil {
			return d, errors.New("deployment config must be a JSON object")
		}
		for key, value := range fields {
			if bytes.Equal(value, []byte("null")) || bytes.Equal(value, []byte(`""`)) {
				return d, fmt.Errorf("deployment field %s cannot be null or empty; omit it to use the default", key)
			}
		}
		if err := DecodeStrict(bytes.NewReader(data), &d); err != nil {
			return d, errors.New("invalid deployment JSON (unknown fields and extra objects are not allowed)")
		}
		if d.SchemaVersion != SchemaVersion {
			return d, errors.New("deployment schema_version must be 1")
		}
		if d.OrganizationName != "" {
			d.Sources["organization_name"] = "file"
		}
		if d.PublicURL != "" {
			d.Sources["public_url"] = "file"
		}
	} else {
		d.SchemaVersion = SchemaVersion
	}
	for _, env := range []struct {
		key, field string
		dst        *string
	}{
		{"GOVWEAVE_LISTEN_ADDR", "", &d.ListenAddr},
		{"GOVWEAVE_DATA_DIR", "", &d.DataDir},
		{"GOVWEAVE_ADMIN_TOKEN_FILE", "", &d.AdminTokenFile},
		{"GOVWEAVE_ORGANIZATION_NAME", "organization_name", &d.OrganizationName},
		{"GOVWEAVE_PUBLIC_URL", "public_url", &d.PublicURL},
	} {
		if value, ok := lookup(env.key); ok {
			if strings.TrimSpace(value) == "" {
				return d, fmt.Errorf("%s cannot be empty; unset it to use the default", env.key)
			}
			*env.dst = value
			if env.field != "" {
				d.Sources[env.field] = "environment"
			}
		}
	}
	host, port, err := net.SplitHostPort(d.ListenAddr)
	if err != nil || (host != "" && host != "localhost" && net.ParseIP(host) == nil) {
		return d, errors.New("listen_addr must be an IP address or localhost and a port, e.g. 127.0.0.1:8080")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return d, errors.New("listen port must be between 1 and 65535")
	}
	if strings.TrimSpace(d.DataDir) == "" {
		return d, errors.New("data_dir cannot be empty")
	}
	if d.OrganizationName != "" {
		d.OrganizationName, err = NormalizeName(d.OrganizationName)
		if err != nil {
			return d, err
		}
	}
	if d.PublicURL != "" {
		d.PublicURL, err = NormalizeURL(d.PublicURL)
		if err != nil {
			return d, err
		}
	}
	return d, nil
}

func NormalizeName(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) < 1 || utf8.RuneCountInString(value) > 100 {
		return "", errors.New("组织名称须为 1–100 个字符")
	}
	for _, c := range value {
		if unicode.IsControl(c) {
			return "", errors.New("组织名称不能包含控制字符")
		}
	}
	return value, nil
}

func NormalizeURL(value string) (string, error) {
	value = strings.TrimSpace(value)
	bad := errors.New("访问地址须为完整的 HTTP(S) 地址，不能包含账号、路径（包括 /v1）、查询参数或片段")
	if len(value) > 2048 || strings.ContainsAny(value, "?#\\") {
		return "", bad
	}
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return "", bad
	}
	host := strings.ToLower(u.Hostname())
	if strings.HasPrefix(u.Host, "[") && net.ParseIP(host) == nil {
		return "", bad
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsUnspecified() || ip.IsMulticast() {
			return "", errors.New("请填写应用可访问的地址，不能使用 0.0.0.0、:: 或组播地址")
		}
	} else {
		if len(host) == 0 || len(host) > 253 {
			return "", bad
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", bad
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return "", bad
				}
			}
		}
	}
	if port := u.Port(); port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return "", bad
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return "", bad
	}
	u.Host = strings.ToLower(u.Host)
	u.Path = ""
	return u.String(), nil
}

func Normalize(s Settings) (Settings, error) {
	var err error
	s.OrganizationName, err = NormalizeName(s.OrganizationName)
	if err != nil {
		return s, err
	}
	s.PublicURL, err = NormalizeURL(s.PublicURL)
	return s, err
}
