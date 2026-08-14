//go:build !linux

package launch

func RunBubblewrapHelper([]string) (bool, error) {
	return false, nil
}
