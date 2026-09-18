package acceptance_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
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
	digest, e := readDevinDarwinArchiveMember(io.LimitReader(gz, 600<<20))
	if e != nil {
		return "", e
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
	targetHash := sha256.New()
	if _, e = io.Copy(targetHash, io.LimitReader(targetFile, 512<<20+1)); e != nil {
		return "", e
	}
	after, e := targetFile.Stat()
	if e != nil || !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() || hex.EncodeToString(targetHash.Sum(nil)) != digest {
		return "", errors.New("target member mismatch")
	}
	return digest, nil
}

func readDevinDarwinArchiveMember(source io.Reader) (string, error) {
	tr := tar.NewReader(source)
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
		if count > 256 {
			return "", errors.New("archive entry cap")
		}
		if filepath.Base(hdr.Name) != "devin" {
			continue
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
			// Continue below and hash the unique regular executable member.
		default:
			return "", errors.New("archive target ambiguity")
		}
		if hdr.Size > 512<<20 || digest != "" {
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
	return digest, nil
}

func TestReadDevinDarwinArchiveMemberRequiresOneRegularExecutable(t *testing.T) {
	archiveBytes := func(entries ...struct {
		name string
		kind byte
		body string
		link string
	}) []byte {
		var raw bytes.Buffer
		writer := tar.NewWriter(&raw)
		for _, entry := range entries {
			header := &tar.Header{Name: entry.name, Mode: 0700, Typeflag: entry.kind, Size: int64(len(entry.body))}
			header.Linkname = entry.link
			if entry.kind == tar.TypeDir {
				header.Size = 0
			}
			if err := writer.WriteHeader(header); err != nil {
				t.Fatal(err)
			}
			if entry.kind == tar.TypeReg {
				if _, err := writer.Write([]byte(entry.body)); err != nil {
					t.Fatal(err)
				}
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return raw.Bytes()
	}
	want := sha256.Sum256([]byte("selected"))
	got, err := readDevinDarwinArchiveMember(bytes.NewReader(archiveBytes(
		struct {
			name string
			kind byte
			body string
			link string
		}{"devin/", tar.TypeDir, "", ""},
		struct {
			name string
			kind byte
			body string
			link string
		}{"devin", tar.TypeReg, "selected", ""},
	)))
	if err != nil || got != hex.EncodeToString(want[:]) {
		t.Fatalf("directory plus regular member: digest=%q err=%v", got, err)
	}
	many := make([]struct {
		name string
		kind byte
		body string
		link string
	}, 0, 246)
	for i := 0; i < 244; i++ {
		many = append(many, struct {
			name string
			kind byte
			body string
			link string
		}{fmt.Sprintf("share/doc/%03d", i), tar.TypeReg, "doc", ""})
	}
	many = append(many,
		struct {
			name string
			kind byte
			body string
			link string
		}{"share/devin", tar.TypeDir, "", ""},
		struct {
			name string
			kind byte
			body string
			link string
		}{"bin/devin", tar.TypeReg, "selected", ""},
	)
	if got, err := readDevinDarwinArchiveMember(bytes.NewReader(archiveBytes(many...))); err != nil || got != hex.EncodeToString(want[:]) {
		t.Fatalf("bounded documentation archive: digest=%q err=%v", got, err)
	}
	for _, test := range []struct {
		name    string
		entries []struct {
			name string
			kind byte
			body string
			link string
		}
		wantErr string
	}{
		{"directory only", []struct {
			name string
			kind byte
			body string
			link string
		}{{"devin", tar.TypeDir, "", ""}}, "missing archive target"},
		{"duplicate regular", []struct {
			name string
			kind byte
			body string
			link string
		}{{"bin/devin", tar.TypeReg, "one", ""}, {"devin", tar.TypeReg, "two", ""}}, "archive target ambiguity"},
		{"matching symlink", []struct {
			name string
			kind byte
			body string
			link string
		}{{"devin", tar.TypeSymlink, "", "bin/devin"}}, "archive target ambiguity"},
		{"matching hardlink", []struct {
			name string
			kind byte
			body string
			link string
		}{{"devin", tar.TypeLink, "", "bin/devin"}}, "archive target ambiguity"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := readDevinDarwinArchiveMember(bytes.NewReader(archiveBytes(test.entries...))); err == nil || err.Error() != test.wantErr {
				t.Fatalf("error=%v want %q", err, test.wantErr)
			}
		})
	}
	tooMany := make([]struct {
		name string
		kind byte
		body string
		link string
	}, 257)
	for i := range tooMany {
		tooMany[i] = struct {
			name string
			kind byte
			body string
			link string
		}{fmt.Sprintf("docs/%03d", i), tar.TypeReg, "doc", ""}
	}
	if _, err := readDevinDarwinArchiveMember(bytes.NewReader(archiveBytes(tooMany...))); err == nil || err.Error() != "archive entry cap" {
		t.Fatalf("257-entry archive error=%v", err)
	}
}
