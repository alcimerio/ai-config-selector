package devin

import "fmt"

// DevinExitCategory is the stable classification for an ordinary Devin exit.
// ACS preserves its exit code and leaves the target's attached terminal output
// unchanged, rather than embedding potentially sensitive output in an error.
const DevinExitCategory = "devin_exited"

// DevinExitError records a completed target exit without exposing target
// output. The CLI recognizes ExitCode and returns it without adding a second
// diagnostic, preserving the existing interactive contract.
type DevinExitError struct {
	Code int
}

func (e *DevinExitError) Error() string {
	if e == nil || e.Code < 0 {
		return DevinExitCategory + ": Devin exited; inspect the attached Devin terminal output"
	}
	return fmt.Sprintf("%s: Devin exited with status %d; inspect the attached Devin terminal output", DevinExitCategory, e.Code)
}

func (e *DevinExitError) ExitCode() int {
	if e == nil || e.Code < 0 {
		return 1
	}
	return e.Code
}
