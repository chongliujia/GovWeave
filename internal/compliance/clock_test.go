package compliance

import (
	"testing"
	"time"
)

func TestEvaluationExposesNextClockBoundary(t *testing.T) {
	pack, input := demo(t)
	pack.EffectiveFrom = evaluationTime.Add(time.Hour).Format(time.RFC3339Nano)
	pack.EffectiveTo = evaluationTime.Add(2 * time.Hour).Format(time.RFC3339Nano)
	future := fact("true")
	future.ObservedAt = evaluationTime.Add(time.Minute).Format(time.RFC3339Nano)
	input.Facts["future.evidence"] = future
	result := evaluate(pack, "digest", input, evaluationTime)
	if result.ReevaluateAt != future.ObservedAt {
		t.Fatal("future evidence boundary missing")
	}
	delete(input.Facts, "future.evidence")
	pack.EffectiveFrom = ""
	pack.Controls[0].Requirement.MaxAgeSeconds = 10
	fresh := fact("true")
	fresh.ObservedAt = evaluationTime.Format(time.RFC3339Nano)
	fresh.ExpiresAt = evaluationTime.Add(5 * time.Second).Format(time.RFC3339Nano)
	input.Facts["transparency.disclosure_verified"] = fresh
	result = evaluate(pack, "digest", input, evaluationTime)
	if result.ReevaluateAt != fresh.ExpiresAt {
		t.Fatal("expiry must precede max-age boundary")
	}
	fresh.ExpiresAt = ""
	input.Facts["transparency.disclosure_verified"] = fresh
	result = evaluate(pack, "digest", input, evaluationTime)
	if result.ReevaluateAt != evaluationTime.Add(10*time.Second).Format(time.RFC3339Nano) {
		t.Fatal("rule freshness deadline missing")
	}
}
