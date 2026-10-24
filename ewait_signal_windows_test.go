//go:build windows

package main

import "testing"

// TestSync_SIGINT_CleansUpAndExitsNonZero is skipped on Windows: herdr-ewait.sh
// requires bash and these tests are already skipped there via requireEwaitTools,
// and syscall.Kill with a process-group signal has no Windows equivalent used here.
func TestSync_SIGINT_CleansUpAndExitsNonZero(t *testing.T) {
	t.Skip("signal-based test not applicable on Windows")
}
