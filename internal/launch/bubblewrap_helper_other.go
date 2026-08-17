//go:build !linux

package launch

func RunBubblewrapHelper([]string) (bool, error) {
	return false, nil
}

func BubblewrapHelperExitCode(error) (int, bool) {
	return 0, false
}
