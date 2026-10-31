package governance

import (
	"encoding/json"
	"testing"
	"time"
)

func TestOutputPolicyRevisionInvalidatesCachedProductAssessment(t *testing.T) {
	f := setup(t)
	f.service.Close()
	product, err := f.service.Save("", f.input())
	if err != nil {
		t.Fatal(err)
	}
	before, err := f.service.Refresh(product.ID)
	if err != nil || before.State != "ready" || before.Snapshot == nil || before.Snapshot.OutputPolicyRevision != 0 {
		t.Fatal("initial output-policy assessment missing", err)
	}
	encoded, _ := json.Marshal(before.Snapshot)
	var stamp map[string]any
	if json.Unmarshal(encoded, &stamp) != nil {
		t.Fatal("invalid source stamp")
	}
	if _, exists := stamp["output_policy_revision"]; exists {
		t.Fatal("zero optional output-policy stamp breaks historical serialization")
	}
	in := f.gateway.OutputPolicies.Snapshot().OutputPolicyInput
	in.Mode, in.Categories, in.ApplicationIDs = "observe", []string{"email"}, []string{f.app.ID}
	saved, err := f.gateway.OutputPolicies.Save(in, f.gateway.Store.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	current := currentStamp(f.gateway, product)
	oldComparable := current
	oldComparable.OutputPolicyRevision = before.Snapshot.OutputPolicyRevision
	if current.OutputPolicyRevision != saved.Revision || oldComparable != *before.Snapshot {
		t.Fatal("output-only edit did not isolate the freshness source")
	}
	pending, err := f.service.Latest(product.ID)
	if err != nil || pending.State != "pending" || pending.Evaluation != nil {
		t.Fatal("stale cached assessment remained current after output-policy edit", err)
	}
	after, err := f.service.Refresh(product.ID)
	if err != nil || after.Snapshot == nil || after.Snapshot.OutputPolicyRevision != saved.Revision {
		t.Fatal("assessment did not retain output-policy source generation", err)
	}
	facts := capture(f.gateway).input(product, time.Now()).Facts
	if string(facts["runtime.output_policy_revision"].Value) != "1" || string(facts["runtime.output_policy_mode"].Value) != `"observe"` || string(facts["runtime.output_policy_covers_product"].Value) != "true" {
		t.Fatal("assessment facts did not capture new output-policy state")
	}
}

func TestOutputPolicyNotificationRefreshesAutomaticAssessment(t *testing.T) {
	f := setup(t)
	product, err := f.service.Save("", f.input())
	if err != nil {
		t.Fatal(err)
	}
	before := await(t, f.service, product.ID, func(r Report) bool { return r.State == "ready" && r.Snapshot.OutputPolicyRevision == 0 })
	in := f.gateway.OutputPolicies.Snapshot().OutputPolicyInput
	in.Mode = "block"
	saved, err := f.gateway.OutputPolicies.Save(in, f.gateway.Store.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	f.gateway.NotifyChange()
	after := await(t, f.service, product.ID, func(r Report) bool { return r.State == "ready" && r.Snapshot.OutputPolicyRevision == saved.Revision })
	if before.Snapshot.AuditBytes != after.Snapshot.AuditBytes || before.Snapshot.GatewayRevision != after.Snapshot.GatewayRevision || before.Snapshot.PolicyRevision != after.Snapshot.PolicyRevision {
		t.Fatal("automatic refresh depended on another source change")
	}
}
