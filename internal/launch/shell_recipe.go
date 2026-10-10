package launch

// ShellRecipe describes the fixed system shell without consulting SHELL or PATH.
// This is intent only: it never admits a platform or starts a process.
func ShellRecipe(operatingSystem string) (string, []string) {
	if operatingSystem == "linux" {
		return "/bin/bash", []string{"--noprofile", "--norc"}
	}
	return "/bin/zsh", []string{"-f"}
}
