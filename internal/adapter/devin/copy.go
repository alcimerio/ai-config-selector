package devin

import (
	"errors"
	"fmt"
	"os"

	"github.com/alcimerio/ai-config-selector/internal/skillmaterial"
)

func copyBundle(source, destination string) error {
	return skillmaterial.CopyBundle(source, destination)
}

func copyCredentialIfPresent(source, destination string) error {
	info, err := os.Stat(source)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errors.New("allowlisted credentials could not be inspected safely")
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("allowlisted credentials path is not a regular file")
	}
	if err := copyFile(source, destination, 0o600); err != nil {
		return errors.New("allowlisted credentials could not be copied safely")
	}
	return nil
}

func copyFile(source, destination string, mode os.FileMode) error {
	return skillmaterial.CopyFile(source, destination, mode)
}
