package compliance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// PackSnapshot returns an independent copy of the installed definition.
func (e *Engine) PackSnapshot(id, version string) (Pack, error) {
	installed, ok := e.packs[packKey(id, version)]
	if !ok {
		return Pack{}, ErrPackNotFound
	}
	data, _ := json.Marshal(installed.pack)
	var pack Pack
	if err := json.Unmarshal(data, &pack); err != nil {
		return Pack{}, err
	}
	return pack, nil
}

// EvaluateSnapshot replays a retained pack at a fixed time without consulting
// the current plugin catalog or making external calls.
func EvaluateSnapshot(pack Pack, input Input, at time.Time) (Evaluation, error) {
	if err := ValidatePack(pack); err != nil {
		return Evaluation{}, err
	}
	if err := ValidateInput(input); err != nil {
		return Evaluation{}, err
	}
	if pack.ID != input.PackID || pack.Version != input.PackVersion || at.IsZero() {
		return Evaluation{}, errors.New("snapshot identity or evaluation time mismatch")
	}
	data, _ := json.Marshal(pack)
	digest := sha256.Sum256(data)
	return evaluate(pack, hex.EncodeToString(digest[:]), input, at), nil
}
