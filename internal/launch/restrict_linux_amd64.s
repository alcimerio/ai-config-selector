#include "textflag.h"
#include "go_asm.h"

// Raw Linux syscalls only. Signals are blocked across fork, all dispositions
// are reset in the child, and only the parent may return to the Go runtime.
// Stack: blocked mask, old mask, zero sigaction/capset storage, protocol byte.
TEXT ·linuxForkExec(SB),NOSPLIT,$80-24
	MOVQ config+0(FP), R12
	MOVQ $-1, 0(SP)
	MOVQ $14, AX // rt_sigprocmask(SIG_SETMASK, all, &old, 8)
	MOVQ $2, DI
	LEAQ 0(SP), SI
	LEAQ 8(SP), DX
	MOVQ $8, R10
	SYSCALL
	TESTQ AX, AX
	JNZ parent_error
	MOVQ $57, AX // fork: exactly one child thread, no CLONE_VM
	SYSCALL
	MOVQ AX, R13
	TESTQ AX, AX
	JZ child
	MOVQ $14, AX // restore parent's mask, including on failed fork
	MOVQ $2, DI
	LEAQ 8(SP), SI
	XORQ DX, DX
	MOVQ $8, R10
	SYSCALL
	TESTQ R13, R13
	JL fork_error
	MOVQ R13, pid+8(FP)
	MOVQ $0, errno+16(FP)
	RET
fork_error:
	MOVQ R13, AX
parent_error:
	NEGQ AX
	MOVQ $0, pid+8(FP)
	MOVQ AX, errno+16(FP)
	RET

child:
	MOVQ linuxExecBoundary_status(R12), R14 // error channel until remapped to fd 3
	MOVQ $1, R15 // fixed setup stage; no paths, argv or environment in failures
	MOVQ $0, 16(SP)
	MOVQ $0, 24(SP)
	MOVQ $0, 32(SP)
	MOVQ $0, 40(SP)
	MOVQ $1, R13
reset_signals:
	CMPQ R13, $9 // SIGKILL
	JE next_signal
	CMPQ R13, $19 // SIGSTOP
	JE next_signal
	MOVQ $13, AX // rt_sigaction(signal, SIG_DFL, NULL, 8)
	MOVQ R13, DI
	LEAQ 16(SP), SI
	XORQ DX, DX
	MOVQ $8, R10
	SYSCALL
	TESTQ AX, AX
	JNZ fail
next_signal:
	INCQ R13
	CMPQ R13, $65
	JNE reset_signals

	CMPQ linuxExecBoundary_terminal(R12), $0
	JL terminal_done
	MOVQ $2, R15
	MOVQ $112, AX // setsid: child owns a new session for its private devpts slave
	SYSCALL
	TESTQ AX, AX
	JS fail
	MOVQ $3, R15
	MOVQ $16, AX // ioctl(private_slave, TIOCSCTTY, 0); never steal an owned tty
	MOVQ linuxExecBoundary_terminal(R12), DI
	MOVQ $0x540e, SI
	XORQ DX, DX
	SYSCALL
	TESTQ AX, AX
	JNZ fail
	XORQ R13, R13
terminal_dup:
	MOVQ $4, R15
	MOVQ $292, AX // dup3(private_slave, stdio, 0)
	MOVQ linuxExecBoundary_terminal(R12), DI
	MOVQ R13, SI
	XORQ DX, DX
	SYSCALL
	TESTQ AX, AX
	JS fail
	INCQ R13
	CMPQ R13, $3
	JNE terminal_dup
terminal_done:
	MOVQ $5, R15
	MOVQ $292, AX // dup3(status, 3, O_CLOEXEC)
	MOVQ linuxExecBoundary_status(R12), DI
	MOVQ $3, SI
	MOVQ $0x80000, DX
	SYSCALL
	TESTQ AX, AX
	JS fail
	MOVQ $3, R14 // status remap succeeded; survives close_range below
	MOVQ $6, R15
	MOVQ $292, AX // dup3(gate, 4, O_CLOEXEC)
	MOVQ linuxExecBoundary_gate(R12), DI
	MOVQ $4, SI
	MOVQ $0x80000, DX
	SYSCALL
	TESTQ AX, AX
	JS fail

	MOVQ $7, R15
	MOVQ $157, AX // prctl(PR_SET_NO_NEW_PRIVS, 1)
	MOVQ $38, DI
	MOVQ $1, SI
	XORQ DX, DX
	XORQ R10, R10
	XORQ R8, R8
	SYSCALL
	TESTQ AX, AX
	JNZ fail
	MOVQ $8, R15
	MOVQ $157, AX // prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)
	MOVQ $47, DI
	MOVQ $4, SI
	SYSCALL
	TESTQ AX, AX
	JNZ fail
	MOVQ $9, R15
	MOVQ $0x20080522, 48(SP) // capset v3; zero two cap data records
	MOVQ $0, 56(SP)
	MOVQ $0, 64(SP)
	MOVQ $0, 72(SP)
	MOVQ $126, AX
	LEAQ 48(SP), DI
	LEAQ 56(SP), SI
	SYSCALL
	TESTQ AX, AX
	JNZ fail

	MOVQ $10, R15
	MOVQ $446, AX // landlock_restrict_self(ruleset, 0)
	MOVQ linuxExecBoundary_ruleset(R12), DI
	XORQ SI, SI
	SYSCALL
	TESTQ AX, AX
	JNZ fail
	MOVQ $11, R15
	MOVQ $436, AX // close_range: remove EVERY non-stdio FD except status/gate
	MOVQ $5, DI
	MOVQ $0xffffffff, SI
	XORQ DX, DX
	SYSCALL
	TESTQ AX, AX
	JNZ fail
	MOVQ $12, R15
	MOVQ $317, AX // seccomp(SET_MODE_FILTER, 0, &program)
	MOVQ $1, DI
	XORQ SI, SI
	MOVQ linuxExecBoundary_program(R12), DX
	SYSCALL
	TESTQ AX, AX
	JNZ fail

	MOVQ $13, R15
	MOVB $82, 48(SP) // ready, only after every restriction succeeded
	MOVQ $1, AX
	MOVQ $3, DI
	LEAQ 48(SP), SI
	MOVQ $1, DX
	SYSCALL
	CMPQ AX, $1
	JNE fail
	MOVQ $14, R15
	MOVQ $0, AX // read exactly one explicit start authorization
	MOVQ $4, DI
	SYSCALL
	CMPQ AX, $1
	JNE fail
	CMPB 48(SP), $83 // 'S'
	JNE fail
	MOVQ $15, R15
	MOVQ $3, AX // close gate (status is CLOEXEC)
	MOVQ $4, DI
	SYSCALL
	TESTQ AX, AX
	JNZ fail
	MOVQ $16, R15
	MOVQ $14, AX // reset signal mask before exec, with only SIG_DFL handlers
	MOVQ $2, DI
	LEAQ 16(SP), SI // zero mask
	XORQ DX, DX
	MOVQ $8, R10
	SYSCALL
	TESTQ AX, AX
	JNZ fail
	MOVQ $17, R15
	MOVQ $59, AX // execve(path, argv, envp)
	MOVQ linuxExecBoundary_path(R12), DI
	MOVQ linuxExecBoundary_argv(R12), SI
	MOVQ linuxExecBoundary_env(R12), DX
	SYSCALL

fail:
	// Fixed error frame: E, stage, little-endian errno (zero for gate failures).
	// This is diagnostic only: every failure still exits without executing Go.
	XORQ R10, R10
	TESTQ AX, AX
	JGE error_frame
	NEGQ AX
	MOVQ AX, R10
error_frame:
	MOVB $69, 48(SP)
	MOVB R15, 49(SP)
	MOVL R10, 50(SP)
	MOVQ $1, AX
	MOVQ R14, DI
	LEAQ 48(SP), SI
	MOVQ $6, DX
	SYSCALL
	MOVQ $231, AX // exit_group(125); never return to Go, even on exec failure
	MOVQ $125, DI
	SYSCALL
	JMP fail
