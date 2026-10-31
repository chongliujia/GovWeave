package compliance

import "time"

// Conservatively include every known time boundary, even unused branches.
// This is a refresh deadline for fixed input, not a promise of legal validity.
func nextClockChange(pack Pack, input Input, now time.Time) string {
	var next time.Time
	consider := func(value time.Time) {
		if value.After(now) && (next.IsZero() || value.Before(next)) {
			next = value
		}
	}
	for _, raw := range []string{pack.EffectiveFrom, pack.EffectiveTo} {
		if raw != "" {
			value, _ := time.Parse(time.RFC3339Nano, raw)
			consider(value)
		}
	}
	for _, fact := range input.Facts {
		observed, _ := time.Parse(time.RFC3339Nano, fact.ObservedAt)
		consider(observed)
		if fact.ExpiresAt != "" {
			value, _ := time.Parse(time.RFC3339Nano, fact.ExpiresAt)
			consider(value)
		}
	}
	var visit func(Expression)
	visit = func(e Expression) {
		if e.MaxAgeSeconds > 0 {
			if fact, ok := input.Facts[e.Fact]; ok {
				observed, _ := time.Parse(time.RFC3339Nano, fact.ObservedAt)
				consider(observed.Add(time.Duration(e.MaxAgeSeconds) * time.Second))
			}
		}
		for _, child := range e.All {
			visit(child)
		}
		for _, child := range e.Any {
			visit(child)
		}
		if e.Not != nil {
			visit(*e.Not)
		}
	}
	for _, control := range pack.Controls {
		if control.AppliesWhen != nil {
			visit(*control.AppliesWhen)
		}
		visit(control.Requirement)
	}
	if next.IsZero() {
		return ""
	}
	return next.UTC().Format(time.RFC3339Nano)
}
