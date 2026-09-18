package acceptance_test

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const devinDarwinArchiveDigest = "c0b97f8197bf3ce895ff14aa19257c511154b49a0a195bba4962acb5e475c68e"

// Verify the independently pinned release archive before comparing its regular
// executable member with the actual installed target. No self-created sidecar.
func verifyDevinDarwinMember(archive, target string) (string, error) {
	f, e := os.Open(archive)
	if e != nil {
		return "", e
	}
	defer f.Close()
	a, e := f.Stat()
	if e != nil || !a.Mode().IsRegular() || a.Size() > 512<<20 {
		return "", errors.New("archive shape")
	}
	h := sha256.New()
	if _, e = io.Copy(h, io.LimitReader(f, 512<<20+1)); e != nil {
		return "", e
	}
	if hex.EncodeToString(h.Sum(nil)) != devinDarwinArchiveDigest {
		return "", errors.New("archive lock mismatch")
	}
	if _, e = f.Seek(0, 0); e != nil {
		return "", e
	}
	gz, e := gzip.NewReader(f)
	if e != nil {
		return "", e
	}
	defer gz.Close()
	tr := tar.NewReader(io.LimitReader(gz, 600<<20))
	count := 0
	digest := ""
	for {
		hdr, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", e
		}
		count++
		if count > 32 {
			return "", errors.New("archive entry cap")
		}
		if filepath.Base(hdr.Name) != "devin" {
			continue
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Size > 512<<20 || digest != "" {
			return "", errors.New("archive target ambiguity")
		}
		mh := sha256.New()
		if _, e = io.Copy(mh, tr); e != nil {
			return "", e
		}
		digest = hex.EncodeToString(mh.Sum(nil))
	}
	if digest == "" {
		return "", errors.New("missing archive target")
	}
	targetFile, e := os.Open(target)
	if e != nil {
		return "", e
	}
	defer targetFile.Close()
	before, e := targetFile.Stat()
	if e != nil || !before.Mode().IsRegular() || before.Mode()&0111 == 0 || before.Size() > 512<<20 {
		return "", errors.New("target shape")
	}
	h.Reset()
	if _, e = io.Copy(h, io.LimitReader(targetFile, 512<<20+1)); e != nil {
		return "", e
	}
	after, e := targetFile.Stat()
	if e != nil || !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() || hex.EncodeToString(h.Sum(nil)) != digest {
		return "", errors.New("target member mismatch")
	}
	return digest, nil
}
