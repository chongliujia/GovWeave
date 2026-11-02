package storage

import (
	"context"
	"os"
	"runtime/trace"
)

// Sync preserves os.File.Sync semantics. The fixed-label region is emitted only
// when an explicit runtime trace is active; no path, content or credential is
// added to diagnostic labels. Caller stacks identify audit versus evidence I/O.
func Sync(file *os.File) error {
	if !trace.IsEnabled() {
		return file.Sync()
	}
	region := trace.StartRegion(context.Background(), "govweave.file_sync")
	defer region.End()
	return file.Sync()
}
