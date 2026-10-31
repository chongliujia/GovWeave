package server

import (
	"encoding/json"
	"testing"

	"govweave/internal/gateway"
)

func TestOutputPolicyAdministrationAndHistoricalContract(t *testing.T) {
	h := handler(t)
	const path = "/api/v1/policies/sensitive-output"
	for _, endpoint := range []string{path, path + "/history", path + "/revisions/0"} {
		for _, key := range []string{"", "gw_app_fixture"} {
			if invoke(h, "GET", endpoint, "", key, nil).Code != 401 {
				t.Fatal("non-administrator accessed output policy")
			}
		}
	}
	w := invoke(h, "GET", path, "", testPassword, nil)
	var initial gateway.OutputPolicySnapshot
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &initial) != nil || initial.Mode != "disabled" || initial.Revision != 0 {
		t.Fatal("unexpected initial output policy", w.Code)
	}
	const body = `{"revision":0,"mode":"block","categories":["email","credential"],"application_ids":[]}`
	for _, headers := range []map[string]string{{"Origin": "https://untrusted.example"}, {"X-GovWeave-Request": ""}} {
		if invoke(h, "PUT", path, body, testPassword, headers).Code != 403 {
			t.Fatal("policy mutation bypassed origin/header guard")
		}
	}
	if invoke(h, "PUT", path, body, testPassword, map[string]string{"Content-Type": "text/plain"}).Code != 415 {
		t.Fatal("non-JSON policy accepted")
	}
	if invoke(h, "PUT", path, `{"revision":0,"unknown":true}`, testPassword, nil).Code != 400 {
		t.Fatal("unknown policy field accepted")
	}
	w = invoke(h, "PUT", path, body, testPassword, nil)
	var saved gateway.OutputPolicySnapshot
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &saved) != nil || saved.Revision != 1 || saved.Mode != "block" || saved.Categories[0] != "credential" {
		t.Fatal("output policy save failed", w.Code)
	}
	if invoke(h, "PUT", path, body, testPassword, nil).Code != 409 {
		t.Fatal("stale policy save accepted")
	}
	w = invoke(h, "GET", path+"/history", "", testPassword, nil)
	var history struct {
		Snapshots []gateway.OutputPolicySnapshot `json:"snapshots"`
		Total     int                            `json:"total"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &history) != nil || history.Total != 2 || len(history.Snapshots) != 2 || history.Snapshots[0].Revision != 1 || history.Snapshots[1].Mode != "disabled" {
		t.Fatal("output history contract failed")
	}
	w = invoke(h, "GET", path+"/revisions/0", "", testPassword, nil)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &initial) != nil || initial.Mode != "disabled" {
		t.Fatal("initial history changed")
	}
	if invoke(h, "GET", path+"/revisions/2", "", testPassword, nil).Code != 404 || invoke(h, "GET", path+"/revisions/invalid", "", testPassword, nil).Code != 400 {
		t.Fatal("invalid revision handling")
	}
	if invoke(h, "POST", "/v1/content/evaluations", `{"text":"Synthetic text"}`, testPassword, nil).Code != 401 {
		t.Fatal("administrator session used for application content API")
	}
}
