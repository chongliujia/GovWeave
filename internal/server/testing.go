package server

import (
	"errors"
	"net/http"

	"govweave/internal/gateway"
	"govweave/internal/governance"
)

func (s *Server) registerTesting(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/compliance/products/{id}/test-plans", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		if _, err := s.governance.Products.Get(r.PathValue("id")); err != nil {
			testingError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"plans": s.governance.Tests.Plans(r.PathValue("id"))})
	}))
	mux.HandleFunc("GET /api/v1/compliance/products/{id}/test-plans/{plan}", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		plan, err := s.governance.Tests.NamedPlan(r.PathValue("id"), r.PathValue("plan"))
		if err != nil {
			testingError(w, err)
			return
		}
		writeJSON(w, 200, plan)
	}))
	mux.HandleFunc("PUT /api/v1/compliance/products/{id}/test-plans/{plan}", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		var input governance.TestPlanInput
		if !s.readMutation(w, r, &input) {
			return
		}
		plan, err := s.governance.Tests.SaveNamedPlan(r.PathValue("id"), r.PathValue("plan"), input)
		if err != nil {
			testingError(w, err)
			return
		}
		writeJSON(w, 200, plan)
	}))
	mux.HandleFunc("GET /api/v1/compliance/test-suites", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"suites": s.governance.Tests.Catalog()})
	}))
	mux.HandleFunc("GET /api/v1/compliance/test-suites/{id}/versions/{version}", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		suite, err := s.governance.Tests.Suite(r.PathValue("id"), r.PathValue("version"))
		if err != nil {
			testingError(w, err)
			return
		}
		writeJSON(w, 200, suite)
	}))
	mux.HandleFunc("GET /api/v1/compliance/products/{id}/test-plan", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		plan, err := s.governance.Tests.Plan(r.PathValue("id"))
		if err != nil {
			testingError(w, err)
			return
		}
		writeJSON(w, 200, plan)
	}))
	mux.HandleFunc("PUT /api/v1/compliance/products/{id}/test-plan", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		var input governance.TestPlanInput
		if !s.readMutation(w, r, &input) {
			return
		}
		plan, err := s.governance.Tests.SavePlan(r.PathValue("id"), input)
		if err != nil {
			testingError(w, err)
			return
		}
		writeJSON(w, 200, plan)
	}))
	mux.HandleFunc("POST /api/v1/compliance/products/{id}/test-runs", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Phase  string `json:"phase"`
			PlanID string `json:"plan_id"`
		}
		if !s.readMutation(w, r, &input) {
			return
		}
		run, err := s.governance.Tests.StartPlan(r.PathValue("id"), input.PlanID, input.Phase, "manual")
		if err != nil {
			testingError(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, run)
	}))
	mux.HandleFunc("GET /api/v1/compliance/products/{id}/test-runs", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		if _, err := s.governance.Products.Get(r.PathValue("id")); err != nil {
			testingError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"runs": s.governance.Tests.List(r.PathValue("id"))})
	}))
	mux.HandleFunc("GET /api/v1/compliance/test-runs/{run}", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		run, err := s.governance.Tests.Get(r.PathValue("run"))
		if err != nil {
			testingError(w, err)
			return
		}
		writeJSON(w, 200, run)
	}))
	mux.HandleFunc("POST /api/v1/compliance/test-runs/{run}/replay", s.authorize(func(w http.ResponseWriter, r *http.Request) {
		var input struct{}
		if !s.readMutation(w, r, &input) {
			return
		}
		result, err := s.governance.Tests.Replay(r.PathValue("run"))
		if err != nil {
			testingError(w, err)
			return
		}
		writeJSON(w, 200, result)
	}))
}

func testingError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, governance.ErrTestBusy):
		apiError(w, 429, "test_busy", err.Error())
	case errors.Is(err, governance.ErrTestCapacity):
		apiError(w, 409, "test_capacity", err.Error())
	case errors.Is(err, governance.ErrTestTargetConflict):
		apiError(w, 409, "test_plan_target_conflict", err.Error())
	case errors.Is(err, governance.ErrTestUnavailable):
		apiError(w, 500, "test_evidence_unavailable", "The retained test evidence could not be verified.")
	case errors.Is(err, gateway.ErrInvalidKey), errors.Is(err, gateway.ErrDenied), errors.Is(err, gateway.ErrDisabled):
		apiError(w, 403, "test_target_not_allowed", "The test application, model or read tool is unavailable or not permitted.")
	default:
		gatewayError(w, err)
	}
}
