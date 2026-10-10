package launch

import (
	"errors"
	"io"
	"os"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

type linuxTerminalConfig struct {
	Attributes unix.Termios
	Size       unix.Winsize
}

func linuxRecipeStdioMode(stdio [3]*os.File) (bool, error) {
	terminals := 0
	for _, file := range stdio {
		if file == nil || linuxCheckStdio(int(file.Fd())) != nil {
			return false, errLinuxRecipe
		}
		if _, err := unix.IoctlGetTermios(int(file.Fd()), unix.TCGETS); err == nil {
			terminals++
		}
	}
	if terminals != 0 && terminals != 3 {
		return false, errLinuxRecipe
	}
	return terminals == 3, nil
}

// Interactive mode requires one inherited controlling terminal for all stdio.
// Fully redirected descriptors use the literal stdio recipe instead. No host
// terminal pathname is opened, and restoration remains cleanup-proof gated.
func linuxRecipeTerminal(stdio [3]*os.File, saved *linuxTerminalState) (*linuxTerminalConfig, error) {
	if saved == nil {
		return nil, errLinuxRecipe
	}
	var original unix.Stat_t
	if unix.Fstat(int(saved.file.Fd()), &original) != nil {
		return nil, errLinuxRecipe
	}
	for _, file := range stdio {
		var stat unix.Stat_t
		if file == nil || unix.Fstat(int(file.Fd()), &stat) != nil || stat.Rdev != original.Rdev ||
			stat.Dev != original.Dev || stat.Ino != original.Ino {
			return nil, errLinuxRecipe
		}
	}
	size, err := unix.IoctlGetWinsize(int(saved.file.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return nil, errLinuxRecipe
	}
	raw := saved.attrs
	raw.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	raw.Oflag &^= unix.OPOST
	raw.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	raw.Cflag &^= unix.CSIZE | unix.PARENB
	raw.Cflag |= unix.CS8
	raw.Cc[unix.VMIN], raw.Cc[unix.VTIME] = 1, 0
	if unix.IoctlSetTermios(int(saved.file.Fd()), unix.TCSETS, &raw) != nil {
		return nil, errLinuxRecipe
	}
	return &linuxTerminalConfig{Attributes: saved.attrs, Size: *size}, nil
}

type linuxPrivateTerminal struct {
	master, slave *os.File
	outputDone    chan error
}

// This runs inside Bubblewrap's private devpts. The child acquires this unused
// slave as its controlling terminal in the raw boundary. The trusted helper
// alone relays inherited host stdio; the target never receives the host tty FD.
func linuxOpenPrivateTerminal(config *linuxTerminalConfig) (*linuxPrivateTerminal, error) {
	master, slave, err := pty.Open()
	if err != nil {
		return nil, errLinuxRecipe
	}
	p := &linuxPrivateTerminal{master: master, slave: slave, outputDone: make(chan error, 1)}
	if unix.IoctlSetTermios(int(slave.Fd()), unix.TCSETS, &config.Attributes) != nil ||
		unix.IoctlSetWinsize(int(master.Fd()), unix.TIOCSWINSZ, &config.Size) != nil {
		p.close()
		return nil, errLinuxRecipe
	}
	go func() { _, _ = io.Copy(master, os.Stdin) }()
	go func() {
		_, err := io.Copy(os.Stdout, master)
		if errors.Is(err, unix.EIO) { // PTY EOF after the last slave closes.
			err = nil
		}
		p.outputDone <- err
	}()
	return p, nil
}

func (p *linuxPrivateTerminal) resize() error {
	size, err := unix.IoctlGetWinsize(0, unix.TIOCGWINSZ)
	if err != nil || unix.IoctlSetWinsize(int(p.master.Fd()), unix.TIOCSWINSZ, size) != nil {
		return errLinuxRecipe
	}
	return nil
}

func (p *linuxPrivateTerminal) drain() error {
	select {
	case err := <-p.outputDone:
		if err == nil {
			return nil
		}
	case <-time.After(linuxContainmentTimeout):
	}
	return errLinuxRecipe
}

func (p *linuxPrivateTerminal) close() {
	_ = p.slave.Close()
	_ = p.master.Close()
}
