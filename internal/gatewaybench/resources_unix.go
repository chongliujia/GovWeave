//go:build linux || darwin

package gatewaybench

import (
	"errors"
	"runtime"
	"syscall"
)

var errUnsupportedResources = errors.New("process resource measurement unavailable")

func processResources() (float64, float64, int64, error) {
	var r syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &r); err != nil {
		return 0, 0, 0, errUnsupportedResources
	}
	rss := int64(r.Maxrss)
	if runtime.GOOS == "linux" {
		rss *= 1024 // Linux reports KiB; Darwin reports bytes.
	}
	return float64(r.Utime.Sec)*1000 + float64(r.Utime.Usec)/1000, float64(r.Stime.Sec)*1000 + float64(r.Stime.Usec)/1000, rss, nil
}
