package session

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestMeasureLifecycle is a measurement harness (not an assertion test).
func TestMeasureLifecycle(t *testing.T) {
	if os.Getenv("ACS_MEASURE") == "" {
		t.Skip("measurement only")
	}
	prior, _ := strconv.Atoi(os.Getenv("ACS_MEASURE_PRIOR"))
	arms, _ := strconv.Atoi(os.Getenv("ACS_MEASURE_ARMS"))
	if arms == 0 {
		arms = 4
	}
	rounds, _ := strconv.Atoi(os.Getenv("ACS_MEASURE_ROUNDS"))
	if rounds == 0 {
		rounds = 20
	}
	base := t.TempDir()
	sessions := filepath.Join(base, ".acs", "sessions")
	work := t.TempDir()
	for i := 0; i < prior; i++ {
		s, err := CreateTracked(sessions, work, nil, "devin")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.ArmOperation(nil); err != nil {
			t.Fatal(err)
		}
		if err := s.Remove(); err != nil {
			t.Fatal(err)
		}
	}
	var create, arm, remove time.Duration
	for r := 0; r < rounds; r++ {
		start := time.Now()
		s, err := CreateTracked(sessions, work, nil, "devin")
		if err != nil {
			t.Fatal(err)
		}
		create += time.Since(start)
		start = time.Now()
		for i := 0; i < arms; i++ {
			if _, err := s.ArmOperation(nil); err != nil {
				t.Fatal(err)
			}
		}
		arm += time.Since(start)
		start = time.Now()
		if err := s.Remove(); err != nil {
			t.Fatal(err)
		}
		remove += time.Since(start)
	}
	d := time.Duration(rounds)
	fmt.Printf("MEASURE prior=%d arms=%d create=%v arm(total)=%v remove=%v\n", prior, arms, create/d, arm/d, remove/d)
}
