package governance

import (
	"errors"
	"sort"
)

// The empty ID preserves the original plan and historical run serialization.
// Named plans provide one model and one read-tool target per product, including
// any legacy default. There is no implicit choice of target when starting a run.
func validPlanID(id string) bool { return id == "" || id == "model" || id == "read_tool" }

func testPlanKey(productID, planID string) string {
	if planID == "" {
		return productID
	}
	return productID + "/" + planID
}

func validatePlanIdentity(id string, in TestPlanInput) error {
	if !validPlanID(id) || (id == "model" && in.TargetKind != "") || (id == "read_tool" && in.TargetKind != "read_tool") {
		return errors.New("plan ID must match its model or read_tool target")
	}
	return nil
}

func (a *ActiveTests) targetConflictLocked(productID, planID, targetKind string) bool {
	for _, plan := range a.plans {
		if plan.ProductID == productID && plan.ID != planID && plan.TargetKind == targetKind {
			return true
		}
	}
	return false
}

func (a *ActiveTests) Plans(productID string) []TestPlan {
	a.mu.Lock()
	defer a.mu.Unlock()
	result := []TestPlan{}
	for _, plan := range a.plans {
		if plan.ProductID == productID {
			result = append(result, plan)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}
