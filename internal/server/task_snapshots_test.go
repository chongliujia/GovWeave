package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"govweave/internal/gateway"
)

func TestTaskSnapshotAPIProtectsScopeMutationsAndExports(t *testing.T) {
	h := handler(t)
	create := func(name string) applicationResponse {
		w := invoke(h, "POST", "/api/v1/applications", fmt.Sprintf(`{"name":%q,"allowed_connections":[]}`, name), testPassword, nil)
		var a applicationResponse
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &a) != nil {
			t.Fatal("create application")
		}
		return a
	}
	a, b := create("Snapshot A"), create("Snapshot B")
	trace := strings.Repeat("a", 32)
	base := "/api/v1/evidence-traces/" + trace
	query := "?application_id=" + a.Application.ID + "&application_id=" + b.Application.ID
	observe := func() {
		w := invoke(h, "POST", "/v1/content/evaluations", `{"text":"private snapshot fixture"}`, a.APIKey, map[string]string{"X-GovWeave-Trace-ID": trace})
		if w.Code != 200 {
			t.Fatal("content observation failed")
		}
	}
	observe()
	w := invoke(h, "GET", base+query, "", testPassword, nil)
	var view gateway.EvidenceTraceView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil {
		t.Fatal("live view unavailable")
	}
	body := fmt.Sprintf(`{"expected_view_sha256":%q}`, view.ViewSHA256)
	for _, headers := range []map[string]string{{"X-GovWeave-Request": ""}, {"Origin": "https://untrusted.example"}} {
		if invoke(h, "POST", base+"/snapshots"+query, body, testPassword, headers).Code != 403 {
			t.Fatal("unprotected archive mutation accepted")
		}
	}
	for _, invalid := range []string{`{}`, `{"expected_view_sha256":"bad"}`, strings.TrimSuffix(body, "}") + `,"view":{"prompt":"injected"}}`} {
		if invoke(h, "POST", base+"/snapshots"+query, invalid, testPassword, nil).Code != 400 {
			t.Fatal("invalid or client-submitted records accepted")
		}
	}
	w = invoke(h, "POST", base+"/snapshots"+query, body, testPassword, nil)
	var archive gateway.ArchivedTaskEvidence
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &archive) != nil || !reflect.DeepEqual(archive.Snapshot.View, view) {
		t.Fatal("save failed or changed the viewed result", w.Code)
	}
	path := base + "/snapshots/" + archive.Summary.ID
	for _, identity := range []string{"", a.APIKey} {
		for _, route := range []struct{ method, path string }{{"POST", base + "/snapshots"}, {"GET", base + "/snapshots"}, {"GET", path}, {"GET", path + "/export/json"}, {"GET", path + "/export/markdown"}} {
			if invoke(h, route.method, route.path+query, body, identity, nil).Code != 401 {
				t.Fatal("snapshot route missing administrator boundary", route.path)
			}
		}
	}
	for _, invalid := range []string{"", "?application_id=*", query + "&include_content=true", query + "&limit=100", query + "&application_id=" + a.Application.ID} {
		if invoke(h, "GET", path+invalid, "", testPassword, nil).Code != 400 {
			t.Fatal("snapshot query accepted extra or implicit scope")
		}
	}
	for _, suffix := range []string{"", "/export/json", "/export/markdown"} {
		if invoke(h, "GET", path+suffix+"?application_id="+a.Application.ID, "", testPassword, nil).Code != 404 {
			t.Fatal("partial scope disclosed snapshot")
		}
	}
	w = invoke(h, "GET", base+"/snapshots?application_id="+a.Application.ID, "", testPassword, nil)
	if w.Code != 200 || strings.Contains(w.Body.String(), archive.Summary.ID) || strings.Contains(w.Body.String(), b.Application.ID) {
		t.Fatal("partial scope disclosed snapshot summary")
	}
	for _, format := range []string{"json", "markdown"} {
		w = invoke(h, "GET", path+"/export/"+format+query, "", testPassword, nil)
		if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Disposition"), "attachment;") || w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), "private snapshot fixture") || strings.Contains(w.Body.String(), a.APIKey) {
			t.Fatal("export privacy, authentication or download contract changed")
		}
		if format == "json" {
			digest := sha256.Sum256(w.Body.Bytes())
			if hex.EncodeToString(digest[:]) != archive.Summary.SHA256 || w.Header().Get("X-GovWeave-SHA256") != archive.Summary.SHA256 {
				t.Fatal("download checksum mismatch")
			}
		}
	}
	observe()
	if invoke(h, "POST", base+"/snapshots"+query, body, testPassword, nil).Code != 409 {
		t.Fatal("new calls silently changed the saved view")
	}
	w = invoke(h, "GET", path+query, "", testPassword, nil)
	var historical gateway.ArchivedTaskEvidence
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &historical) != nil || !reflect.DeepEqual(historical, archive) {
		t.Fatal("historical read recomputed a live task")
	}
}
