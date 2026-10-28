package cli

import (
	"errors"
	"reflect"
	"testing"
)

// The launchd sweep addresses jobs as com.lerd.<file>, which the native FPM
// pools are not, so uninstall deleted their plists and left them serving. A
// reinstall then raced the still-loaded job and came up with no FPM at all.
func TestUninstallStopsEveryNativePool(t *testing.T) {
	var stopped []string
	stopNativePools([]string{"8.3", "8.4"}, func(v string) error { stopped = append(stopped, v); return nil })
	if want := []string{"8.3", "8.4"}; !reflect.DeepEqual(stopped, want) {
		t.Errorf("stopped %v, want %v", stopped, want)
	}
}

// The watcher repairs DNS it finds broken, so a teardown that ran while it was
// up got undone a second later and left .test routed to a dead lerd-dns.
func TestUninstallStopsTheWatcherBeforeDNSTeardown(t *testing.T) {
	var calls []string
	err := stopWatcherThenTeardownDNS(
		func(unit string) error { calls = append(calls, "stop "+unit); return nil },
		func(string) bool { return false },
		func() { calls = append(calls, "teardown") },
	)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"stop lerd-watcher", "teardown"}; !reflect.DeepEqual(calls, want) {
		t.Errorf("calls %v, want %v", calls, want)
	}
}

func TestUninstallRefusesDNSTeardownWhileTheWatcherStillRuns(t *testing.T) {
	tornDown := false
	err := stopWatcherThenTeardownDNS(
		func(string) error { return errors.New("no user bus") },
		func(string) bool { return true },
		func() { tornDown = true },
	)
	if err == nil || tornDown {
		t.Errorf("err %v, tornDown %v: want an error and the DNS setup left alone", err, tornDown)
	}
}

// A watcher that was never running has nothing to heal with, so a failed stop
// must not block the uninstall.
func TestUninstallTearsDNSDownWhenTheWatcherIsAlreadyGone(t *testing.T) {
	tornDown := false
	err := stopWatcherThenTeardownDNS(
		func(string) error { return errors.New("unit not loaded") },
		func(string) bool { return false },
		func() { tornDown = true },
	)
	if err != nil || !tornDown {
		t.Errorf("err %v, tornDown %v: want the teardown to run", err, tornDown)
	}
}
