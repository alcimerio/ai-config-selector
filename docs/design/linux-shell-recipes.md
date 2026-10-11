# Experimental Linux shell and command recipes (#190)

[Documentation index](../README.md)

This implements [roadmap item 11](linux-support.md#stack-5--targets). Production
Linux admission remains closed. The private `linuxRecipeAdmission` value is false
by default; only test code enables it. There is no registered Linux backend,
production helper entry point, CLI flag, or environment bypass. Neither releases
nor the supported host matrix change. Darwin retains `/bin/zsh -f` and its
existing sandbox, authority and terminal implementation.

## Recipes and runtime files

The fixed Linux shell is `/bin/bash --noprofile --norc`. It never consults `SHELL`
or the host PATH. Bash chooses interactive mode from its stdio; redirected input
remains a script stream. Its private HOME and reserved environment destinations
prevent ambient startup files, `BASH_ENV`, `ENV`, loader variables and shell
options from reaching it. Generic commands receive literal argv, including empty
arguments and shell metacharacters. There is no implicit shell evaluation.

The experimental recipe accepts native amd64 ELF files. It parses their
interpreter and transitive `DT_NEEDED` entries without executing `ldd` or targets.
Only the glibc amd64 interpreter and fixed multiarch library search directories
are admitted. Scripts, foreign architectures, custom interpreters, RPATH,
RUNPATH, audit/filter dependencies, and dependency names containing paths are
rejected. Bounds apply to files, interpreter data and dependency count.

The compiler receives exact read-only runtime files. Merged-/usr aliases become
exact read-only file mounts from pinned canonical sources, not directory binds
or imported host symlinks. Interactive sessions additionally receive one xterm
terminfo entry. Runtime inputs cannot overlap writable authority. The recipe's
unspecified workspace access defaults to read-only without changing the shared
legacy workspace contract. Explicit grants continue through the existing Linux
compiler, including its conservative exclusion/protection rejection rules.

This is a bounded initial runtime, not compatibility with arbitrary Linux
programs. DNS/NSS configuration, certificates, locales beyond C, application data,
dlopen plugins, additional shell commands and non-glibc loaders are not added
implicitly. Executable grants do not recursively qualify arbitrary toolchains.

## Launcher, terminal and cleanup

`linuxRunRecipe` requires the real host probes even after experimental admission:
native Ubuntu 24.04 on amd64, kernel 6.12+, Landlock ABI 6+, seccomp, system
Bubblewrap, unprivileged namespaces, and delegated cgroup v2. WSL and containers
remain rejected. Every recipe uses the sealed transport and the existing
supervisor's atomic cgroup placement, start gate, pidfd signaling, bounded cleanup
and authenticated settlement proof. Preparation failures restore retained
terminal state and finalize only the no-child case. Uncertain settlement retains
the Session and its lease.

Interactive mode requires all three stdio descriptors to identify the supplied
controlling terminal. The outer supervisor retains its original attributes,
temporarily makes it raw, and restores/flushes it only after proven settlement.
The trusted namespace helper allocates a separate PTY in Bubblewrap's private
devpts and relays input/output. The raw child creates its own session and acquires
that unused slave before installing the final restrictions. Window changes are
copied to the private PTY before SIGWINCH forwarding. The target never receives
the host terminal descriptor. Fully redirected recipes preserve their original
files/pipes. Mixed terminal/redirected stdio is rejected pending qualification.

Bubblewrap's setup filter allows only non-stealing `TIOCSCTTY` on a high setup
descriptor. The final child filter still denies TIOCSCTTY, TIOCSTI, TIOCLINUX,
terminal detachment, listeners, ptrace, namespace changes and the other existing
denials. There is no weaker target filter. The two-stage placement follows
[Bubblewrap's setup/exec ordering](https://github.com/containers/bubblewrap/blob/v0.8.0/bubblewrap.c).

## Evidence and limits

Unit tests cover default-off admission (including attempted environment bypass),
fixed recipes, literal argv, ELF rejection cases, read-only runtime plans, the
two seccomp stages, and Linux help/passive diagnostics. Filesystem-plan unit
fixtures use synthetic directory identities; they are not native mount proof.

Native primitive tests execute the actual dynamic Bash and a static generic
command behind Landlock/seccomp. They check clean startup, literal/empty argv,
read-only workspace denial with a writable HOME control, redirected exit status,
and interactive PTY input, terminal size and Bash job-control activation. They
do not claim namespace or cgroup confinement. Existing tests still cover
restricted syscalls, inherited restrictions, cgroup lifetime and proof failures.

The separate composition suite runs those recipes through real Bubblewrap,
cgroups and cleanup proof, including interactive resize and exact exit status.
It accepts only unmodified native filesystem observations. Missing prerequisites
produce explicit skips only when `ACS_LINUX_NATIVE_REQUIRED` is unset; setting it
to `1` makes missing prerequisites fatal:

```sh
ACS_LINUX_NATIVE_REQUIRED=1 CGO_ENABLED=0 go test ./internal/launch -run 'LinuxNativeRecipe' -v -count=1
```

A skipped composition suite is not Ubuntu HWE certification. Production snapshot
capture/revalidation, mutable executable contents, the compiler's unsupported
exclusion cases, mixed interactive redirection, background jobs holding PTYs,
and broader runtime/target qualification remain activation gates. No egress
filtering, credential-provider change, arm64 support or production enablement is
included here.
