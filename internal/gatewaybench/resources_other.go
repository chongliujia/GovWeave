//go:build !linux && !darwin

package gatewaybench

import "errors"

var errUnsupportedResources = errors.New("gateway benchmark supports Linux and macOS only")

func processResources() (float64, float64, int64, error) {
	return 0, 0, 0, errUnsupportedResources
}
