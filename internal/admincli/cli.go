// Package admincli manages a running instance over its authenticated HTTP API.
// It never opens the service's data directory. Session files are explicit and private.
package admincli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"govweave/internal/auth"
	"govweave/internal/config"
	"govweave/internal/gateway"
	"govweave/internal/governance"
)

const usage = `Usage: govweave admin [--url URL] [--session-file FILE] [--password-stdin | --password-file FILE] COMMAND

Commands:
  status                           Check service health (no password needed)
  setup                            Set the initial administrator password
  login                            Save a session to a new private --session-file
  logout                           Revoke and remove the selected --session-file
  applications list                List applications and grants
  connections list                 List configured model connections
  applications create --file FILE  Create from private JSON (returns a one-time key)
  connections create --file FILE   Create a model connection from private JSON
  applications update --id ID --file FILE
  connections update --id ID --file FILE
  applications rotate --id ID --revision N   Issue a new one-time application key
  applications revoke --id ID --revision N   Revoke application access
  requests list [--application ID] [--limit 1..100]
  policy show [--application ID]    Read the default or effective application policy
  policy history [--application ID]
  policy set [--application ID] --revision N [--mode MODE] [--detector VERSION]
             [--categories credential,email,phone] [--public-emails ADDRESS,...]
             [--scope all|APP_ID,...]   (scope is for the default policy only)
  policy inherit --application ID --revision N
  policy restore --application ID --revision N --from-revision OLD
  products list | products show --id ID
  reports list --product ID | reports create --product ID | reports show --id ID
  remediations list --product ID | remediations show --product ID --id ID
  remediations create --product ID --file FILE
  remediations update --product ID --id ID --file FILE
  remediations recheck --product ID --id ID --revision N [--test-run ID]
  tests list --product ID | tests show --id ID | tests plans --product ID
  tests run --product ID --plan ID --phase pre_deployment|operation
                                     Explicitly starts configured model/tool calls

Global flags precede the command; command flags follow its name.
All successful commands emit JSON. Writes require the revision you inspected.
Password input is a single line on stdin or a private file; there is no password flag.
HTTP is permitted only on loopback. Use HTTPS or an SSH tunnel for remote management.
With a session file, commands reuse that origin-bound session until logout or expiry.
Without one, each command logs in once and revokes its temporary session afterward.
`

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,100}$`)
var errorCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,99}$`)

type client struct {
	base    *url.URL
	http    *http.Client
	timeout time.Duration
}

func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("admin", flag.ContinueOnError)
	flags.SetOutput(stderr)
	endpoint := flags.String("url", "http://127.0.0.1:8080", "gateway root URL")
	passwordStdin := flags.Bool("password-stdin", false, "read password from stdin")
	passwordFile := flags.String("password-file", "", "read password from a private file")
	sessionFile := flags.String("session-file", "", "explicit private session file")
	timeout := flags.Duration("timeout", 15*time.Second, "per-request timeout (1s to 60s)")
	flags.Usage = func() { fmt.Fprint(stderr, usage) }
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	command := flags.Args()
	if len(command) == 0 {
		flags.Usage()
		return errors.New("choose an administration command")
	}
	if *timeout < time.Second || *timeout > time.Minute {
		return errors.New("timeout must be between 1s and 60s")
	}
	target, err := url.Parse(*endpoint)
	if err != nil || target.Host == "" || target.User != nil || target.RawQuery != "" || target.ForceQuery || target.Fragment != "" || target.RawPath != "" || (target.Path != "" && target.Path != "/") || (target.Scheme != "https" && target.Scheme != "http") {
		return errors.New("use an HTTP(S) gateway root URL without credentials, path, query or fragment")
	}
	if target.Scheme == "http" && target.Hostname() != "localhost" && !net.ParseIP(target.Hostname()).IsLoopback() {
		return errors.New("remote administration requires HTTPS or a loopback SSH tunnel")
	}
	target.Path = ""
	jar, _ := cookiejar.New(nil)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil // Do not forward local administrator credentials through environment proxies.
	defer transport.CloseIdleConnections()
	c := &client{base: target, timeout: *timeout, http: &http.Client{Jar: jar, Transport: transport, Timeout: *timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are not permitted") }}}
	// Parse/validate the full command before authentication or any mutation.
	operation, err := parseCommand(command)
	if err != nil {
		return err
	}
	if *passwordStdin && *passwordFile != "" {
		return errors.New("choose one password input method")
	}
	if command[0] == "status" {
		data, err := c.request("GET", "/healthz", nil)
		if err != nil {
			return err
		}
		return emit(stdout, data)
	}
	if command[0] == "login" && *sessionFile == "" {
		return errors.New("login requires --session-file with a new private file path")
	}
	if command[0] == "logout" && *sessionFile == "" {
		return errors.New("logout requires --session-file")
	}
	if *sessionFile != "" {
		if command[0] == "setup" {
			return errors.New("setup uses a temporary session; run login afterward to create a session file")
		}
		if command[0] == "login" {
			if _, err := os.Lstat(*sessionFile); !errors.Is(err, os.ErrNotExist) {
				return errors.New("session file already exists or cannot be inspected; choose a new path")
			}
		} else {
			if *passwordStdin || *passwordFile != "" {
				return errors.New("use the session file without password flags")
			}
			if err := c.loadSession(*sessionFile); err != nil {
				return err
			}
			if command[0] == "logout" {
				data, err := c.request("POST", "/api/v1/auth/logout", struct{}{})
				if err != nil {
					return err
				}
				if os.Remove(*sessionFile) != nil {
					return errors.New("session revoked, but its local file could not be removed")
				}
				return emit(stdout, data)
			}
			data, err := operation(c)
			if err != nil {
				return err
			}
			return emit(stdout, data)
		}
	}
	if !*passwordStdin && *passwordFile == "" {
		return errors.New("use --password-stdin or --password-file; passwords are never accepted in arguments")
	}
	reader := stdin
	if *passwordFile != "" {
		file, err := os.Open(*passwordFile)
		if err != nil {
			return errors.New("cannot open password file")
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("password file must be regular and accessible only to its owner (0600)")
		}
		reader = file
	}
	secret, err := io.ReadAll(io.LimitReader(reader, 1027))
	if err != nil || len(secret) > 1026 {
		return errors.New("could not read a bounded password line")
	}
	secret = bytes.TrimSuffix(secret, []byte("\n"))
	secret = bytes.TrimSuffix(secret, []byte("\r"))
	if len(secret) == 0 || len(secret) > 1024 || bytes.ContainsAny(secret, "\r\n") {
		return errors.New("provide one nonempty password line")
	}
	action := "login"
	if command[0] == "setup" {
		action = "setup"
	}
	_, loginErr := c.request("POST", "/api/v1/auth/"+action, map[string]string{"password": string(secret)})
	clear(secret)
	if loginErr != nil {
		return loginErr
	}
	if command[0] == "login" {
		if err := c.saveSession(*sessionFile); err != nil {
			_, _ = c.request("POST", "/api/v1/auth/logout", struct{}{})
			return err
		}
		return emit(stdout, json.RawMessage(`{"authenticated":true,"session_saved":true}`))
	}
	result, operationErr := operation(c)
	// No cached credentials: revoke even if the requested operation failed.
	_, logoutErr := c.request("POST", "/api/v1/auth/logout", struct{}{})
	if operationErr != nil {
		return operationErr
	}
	if err := emit(stdout, result); err != nil {
		return err
	}
	if logoutErr != nil {
		return errors.New("operation completed, but session revocation could not be confirmed; the session was not saved locally")
	}
	return nil
}

type sessionState struct {
	SchemaVersion int       `json:"schema_version"`
	Origin        string    `json:"origin"`
	Session       string    `json:"session"`
	ExpiresAt     time.Time `json:"expires_at"`
}

func (c *client) saveSession(path string) error {
	state := sessionState{SchemaVersion: 1, Origin: c.base.String(), ExpiresAt: time.Now().Add(auth.SessionLifetime)}
	location := c.base.ResolveReference(&url.URL{Path: "/api/"})
	for _, cookie := range c.http.Jar.Cookies(location) {
		if cookie.Name == "govweave_session" {
			state.Session = cookie.Value
		}
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(state.Session) {
		return errors.New("login did not establish an administrator session")
	}
	data, _ := json.Marshal(state)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cannot create a new private session file")
	}
	_, err = file.Write(append(data, '\n'))
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		_ = os.Remove(path)
		return errors.New("could not persist private session file")
	}
	return nil
}

func (c *client) loadSession(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("session file must be a private regular file (0600)")
	}
	file, err := os.Open(path)
	if err != nil {
		return errors.New("cannot read session file")
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4096 {
		return errors.New("invalid private session file")
	}
	var state sessionState
	if config.DecodeStrict(io.LimitReader(file, 4097), &state) != nil || state.SchemaVersion != 1 || state.Origin != c.base.String() || !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(state.Session) {
		return errors.New("session file is invalid or belongs to a different gateway origin")
	}
	if !time.Now().Before(state.ExpiresAt) {
		return errors.New("session has expired; log in to a new session file")
	}
	c.http.Jar.SetCookies(c.base, []*http.Cookie{{Name: "govweave_session", Value: state.Session, Path: "/api/", HttpOnly: true, Secure: c.base.Scheme == "https", Expires: state.ExpiresAt}})
	return nil
}

func emit(w io.Writer, data json.RawMessage) error {
	var out bytes.Buffer
	if err := json.Indent(&out, data, "", "  "); err != nil {
		return errors.New("invalid gateway JSON")
	}
	out.WriteByte('\n')
	_, err := w.Write(out.Bytes())
	return err
}

func (c *client) request(method, path string, input any) (json.RawMessage, error) {
	var body []byte
	if input != nil {
		var err error
		body, err = json.Marshal(input)
		if err != nil {
			return nil, errors.New("invalid request data")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.base.String()+path, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("invalid management request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GovWeave-Request", "console")
	req.Header.Set("Origin", c.base.String())
	response, err := c.http.Do(req)
	if err != nil {
		return nil, errors.New("management request failed or timed out; inspect current state before retrying a write")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if err != nil || len(data) > 4<<20 {
		return nil, errors.New("gateway response was incomplete or exceeded 4 MiB")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var result struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(data, &result)
		code := "request_failed"
		if errorCode.MatchString(result.Error.Code) {
			code = result.Error.Code
		}
		return nil, fmt.Errorf("HTTP %d: %s", response.StatusCode, code)
	}
	if strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0])) != "application/json" || !json.Valid(data) {
		return nil, errors.New("gateway returned an invalid JSON response")
	}
	// Re-encode so a terminal cannot interpret literal control characters.
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return nil, errors.New("invalid gateway JSON")
	}
	return json.Marshal(value)
}

type operation func(*client) (json.RawMessage, error)

func parseCommand(args []string) (operation, error) {
	if len(args) == 1 && (args[0] == "login" || args[0] == "logout") {
		return func(c *client) (json.RawMessage, error) { return json.RawMessage(`{}`), nil }, nil
	}
	if len(args) == 1 && args[0] == "status" {
		return func(c *client) (json.RawMessage, error) { return c.request("GET", "/healthz", nil) }, nil
	}
	if len(args) == 1 && args[0] == "setup" {
		return func(c *client) (json.RawMessage, error) { return json.RawMessage(`{"setup_complete":true}`), nil }, nil
	}
	if len(args) < 2 {
		return nil, errors.New("incomplete command; use govweave admin --help")
	}
	group, action := args[0], args[1]
	fs := flag.NewFlagSet(group+" "+action, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	app := fs.String("application", "", "application ID")
	limit := fs.Int("limit", 20, "request limit")
	revision := fs.String("revision", "", "current policy revision")
	from := fs.String("from-revision", "", "historical revision")
	mode := fs.String("mode", "", "policy mode")
	detector := fs.String("detector", "", "detector version")
	categories := fs.String("categories", "", "comma-separated categories")
	emails := fs.String("public-emails", "", "comma-separated exact emails")
	scope := fs.String("scope", "", "all or application IDs")
	id := fs.String("id", "", "resource ID")
	file := fs.String("file", "", "private configuration JSON file")
	product := fs.String("product", "", "product ID")
	testRun := fs.String("test-run", "", "completed retest ID")
	plan := fs.String("plan", "", "configured test plan ID")
	phase := fs.String("phase", "", "test phase")
	if fs.Parse(args[2:]) != nil || fs.NArg() != 0 {
		return nil, errors.New("invalid command flags; use govweave admin --help")
	}
	supplied := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { supplied[f.Name] = true })
	allowed := map[string]bool{}
	allow := func(names ...string) {
		for _, name := range names {
			allowed[name] = true
		}
	}
	switch group + " " + action {
	case "products list":
	case "products show", "reports show", "tests show":
		allow("id")
	case "reports list", "reports create", "remediations list", "tests list", "tests plans":
		allow("product")
	case "remediations show":
		allow("product", "id")
	case "remediations create":
		allow("product", "file")
	case "remediations update":
		allow("product", "id", "file")
	case "remediations recheck":
		allow("product", "id", "revision", "test-run")
	case "tests run":
		allow("product", "plan", "phase")
	case "applications list", "connections list":
	case "applications create", "connections create":
		allow("file")
	case "applications update", "connections update":
		allow("id", "file")
	case "applications rotate", "applications revoke":
		allow("id", "revision")
	case "requests list":
		allow("application", "limit")
	case "policy show", "policy history":
		allow("application")
	case "policy set":
		allow("application", "revision", "mode", "detector", "categories", "public-emails", "scope")
	case "policy inherit":
		allow("application", "revision")
	case "policy restore":
		allow("application", "revision", "from-revision")
	default:
		return nil, errors.New("unknown command; use govweave admin --help")
	}
	for name := range supplied {
		if !allowed[name] {
			return nil, errors.New("flag is not supported for this command")
		}
	}
	if supplied["application"] && !identifier.MatchString(*app) {
		return nil, errors.New("invalid application ID")
	}
	if group == "products" || group == "reports" || group == "remediations" || group == "tests" {
		validID := func(value string) bool {
			return regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`).MatchString(value)
		}
		for _, name := range []string{"product", "id", "plan"} {
			if allowed[name] && !validID(fs.Lookup(name).Value.String()) {
				return nil, errors.New("provide a valid --" + name)
			}
		}
		path, method := "/api/v1/compliance/products", "GET"
		var payload any
		switch group {
		case "products":
			if action == "show" {
				path += "/" + *id
			}
		case "reports":
			if action == "show" {
				path = "/api/v1/compliance/reports/" + *id
			} else {
				path += "/" + *product + "/reports"
			}
			if action == "create" {
				method, payload = "POST", struct{}{}
			}
		case "tests":
			if action == "show" {
				path = "/api/v1/compliance/test-runs/" + *id
			} else {
				path += "/" + *product + "/test-runs"
			}
			if action == "plans" {
				path = "/api/v1/compliance/products/" + *product + "/test-plans"
			}
			if action == "run" {
				if *phase != "operation" && *phase != "pre_deployment" {
					return nil, errors.New("choose --phase pre_deployment or operation")
				}
				method, payload = "POST", map[string]string{"phase": *phase, "plan_id": *plan}
			}
		case "remediations":
			path += "/" + *product + "/remediations"
			if action == "show" || action == "update" || action == "recheck" {
				path += "/" + *id
			}
			if action == "recheck" {
				rev, err := strconv.ParseUint(*revision, 10, 64)
				if err != nil || supplied["test-run"] && !validID(*testRun) {
					return nil, errors.New("provide the current --revision and a valid optional --test-run")
				}
				path += "/recheck"
				method, payload = "POST", governance.RemediationCheck{Revision: rev, TestRunID: *testRun}
			}
			if action == "create" || action == "update" {
				method, payload = "POST", &governance.RemediationCreate{}
				if action == "update" {
					method, payload = "PUT", &governance.RemediationInput{}
				}
				info, err := os.Lstat(*file)
				if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 16*1024 {
					return nil, errors.New("remediation input must be a private regular JSON file of at most 16 KiB")
				}
				f, err := os.Open(*file)
				if err != nil {
					return nil, errors.New("cannot read remediation input")
				}
				defer f.Close()
				if config.DecodeStrict(io.LimitReader(f, 16*1024+1), payload) != nil {
					return nil, errors.New("invalid remediation JSON")
				}
			}
		}
		return func(c *client) (json.RawMessage, error) { return c.request(method, path, payload) }, nil
	}
	if group == "applications" || group == "connections" {
		if action != "list" {
			path := "/api/v1/" + group
			method := "POST"
			if action != "create" {
				if !identifier.MatchString(*id) {
					return nil, errors.New("provide a valid --id")
				}
				path += "/" + *id
				method = "PUT"
			}
			if action == "rotate" || action == "revoke" {
				rev, err := strconv.ParseUint(*revision, 10, 64)
				if err != nil {
					return nil, errors.New("provide the current application --revision")
				}
				return func(c *client) (json.RawMessage, error) {
					return c.request("POST", path+"/"+action, map[string]uint64{"revision": rev})
				}, nil
			}
			f, err := os.Open(*file)
			if err != nil {
				return nil, errors.New("cannot open configuration file")
			}
			defer f.Close()
			info, err := f.Stat()
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 16*1024 {
				return nil, errors.New("configuration file must be private (0600), regular and at most 16 KiB")
			}
			var payload any = &gateway.ApplicationInput{}
			if group == "connections" {
				payload = &gateway.ConnectionInput{}
			}
			if config.DecodeStrict(io.LimitReader(f, 16*1024+1), payload) != nil {
				return nil, errors.New("invalid configuration JSON; use the corresponding management API input schema")
			}
			return func(c *client) (json.RawMessage, error) { return c.request(method, path, payload) }, nil
		}
		return func(c *client) (json.RawMessage, error) {
			data, err := c.request("GET", "/api/v1/gateway", nil)
			if err != nil {
				return nil, err
			}
			var value map[string]json.RawMessage
			if json.Unmarshal(data, &value) != nil || value[group] == nil || value["revision"] == nil {
				return nil, errors.New("invalid gateway resource response")
			}
			return json.Marshal(map[string]json.RawMessage{"revision": value["revision"], group: value[group]})
		}, nil
	}
	if group == "requests" {
		if *limit < 1 || *limit > 100 {
			return nil, errors.New("limit must be between 1 and 100")
		}
		return func(c *client) (json.RawMessage, error) {
			return c.request("GET", fmt.Sprintf("/api/v1/requests?limit=%d&application_id=%s", *limit, url.QueryEscape(*app)), nil)
		}, nil
	}
	path := "/api/v1/policies/sensitive-output"
	if *app != "" {
		path += "/applications/" + url.PathEscape(*app)
	}
	if action == "show" || action == "history" {
		if action == "history" {
			path += "/history"
		}
		return func(c *client) (json.RawMessage, error) { return c.request("GET", path, nil) }, nil
	}
	current, err := strconv.ParseUint(*revision, 10, 64)
	if err != nil {
		return nil, errors.New("writes require --revision with the current policy revision")
	}
	if action == "inherit" || action == "restore" {
		if *app == "" {
			return nil, errors.New("this command requires --application")
		}
		payload := map[string]uint64{"revision": current}
		method := "DELETE"
		if action == "restore" {
			previous, err := strconv.ParseUint(*from, 10, 64)
			if err != nil {
				return nil, errors.New("restore requires --from-revision")
			}
			payload["from_revision"] = previous
			method = "POST"
			path += "/restore"
		}
		return func(c *client) (json.RawMessage, error) { return c.request(method, path, payload) }, nil
	}
	if *app != "" && supplied["scope"] {
		return nil, errors.New("application-specific policies cannot change scope")
	}
	if !supplied["mode"] && !supplied["detector"] && !supplied["categories"] && !supplied["public-emails"] && !supplied["scope"] {
		return nil, errors.New("specify at least one policy setting")
	}
	return func(c *client) (json.RawMessage, error) {
		data, err := c.request("GET", path, nil)
		if err != nil {
			return nil, err
		}
		var policy gateway.OutputPolicySnapshot
		if *app != "" {
			var view struct {
				Policy gateway.OutputPolicySnapshot `json:"policy"`
			}
			err = json.Unmarshal(data, &view)
			policy = view.Policy
		} else {
			err = json.Unmarshal(data, &policy)
		}
		if err != nil || policy.ID != "sensitive-output" {
			return nil, errors.New("invalid policy response")
		}
		if policy.Revision != current {
			return nil, errors.New("policy revision changed; read the current policy before retrying")
		}
		if *app != "" && !policy.Applies(*app) {
			policy.Mode = "disabled"
		}
		if supplied["mode"] {
			policy.Mode = *mode
		}
		if supplied["detector"] {
			policy.DetectorVersion = *detector
		}
		split := func(s string) []string {
			if s == "" {
				return []string{}
			}
			return strings.Split(s, ",")
		}
		if supplied["categories"] {
			policy.Categories = split(*categories)
		}
		if supplied["public-emails"] {
			policy.PublicEmails = split(*emails)
		}
		payload := map[string]any{"revision": current, "mode": policy.Mode, "detector_version": policy.DetectorVersion, "categories": policy.Categories, "public_emails": policy.PublicEmails}
		if *app == "" {
			if supplied["scope"] {
				if *scope == "all" {
					policy.ApplicationIDs = []string{}
				} else {
					policy.ApplicationIDs = split(*scope)
				}
			}
			payload["application_ids"] = policy.ApplicationIDs
		}
		return c.request("PUT", path, payload)
	}, nil
}
