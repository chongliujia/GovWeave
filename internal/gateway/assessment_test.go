package gateway

import (
	"errors"
	"testing"
)

func TestAssessmentResolutionStillChecksGrantsAndCopiesState(t *testing.T) {
	s, c, app, _ := setupStore(t, t.TempDir(), "https://models.example/v1")
	resolved, err := s.ResolveAssessment(app.ID, c.Alias)
	if err != nil {
		t.Fatal(err)
	}
	resolved.Application.AllowedConnections[0] = "mutated"
	if _, err := s.ResolveAssessment(app.ID, c.Alias); err != nil {
		t.Fatal("assessment caller mutated stored grants", err)
	}
	if _, err := s.ResolveAssessment(app.ID, "not-granted"); !errors.Is(err, ErrDenied) {
		t.Fatal("unknown model allowed")
	}
	if _, _, err := s.ChangeKey(app.ID, app.Revision, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveAssessment(app.ID, c.Alias); !errors.Is(err, ErrInvalidKey) {
		t.Fatal("revocation bypassed")
	}
}
