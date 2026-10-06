// Package cli provides shared command-line helpers for the tunnel tools.
package cli

import "github.com/spf13/cobra"

// AddCompletion installs completion even on tools without application subcommands.
// Generation never runs the application's validation or startup hooks.
func AddCompletion(root *cobra.Command) {
	completion := &cobra.Command{
		Use: "completion", Short: "Generate shell completion scripts",
		Args: cobra.NoArgs,
		Long: "Generate shell completion scripts for Bash, Zsh, Fish, or PowerShell.\nSee a shell's help for installation instructions.",
	}
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		cmd := &cobra.Command{Use: shell, Short: "Generate " + shell + " completion", Args: cobra.NoArgs}
		cmd.Example = "  " + root.Name() + " completion " + shell
		if shell == "bash" {
			cmd.Long = "Generate Bash completion. With bash-completion installed, load it in your current shell:\n\n  source <(" + root.Name() + " completion bash)\n\nFor future sessions on Linux:\n\n  mkdir -p ~/.local/share/bash-completion/completions\n  " + root.Name() + " completion bash > ~/.local/share/bash-completion/completions/" + root.Name() + "\n\nInstall the tool on PATH so completion can invoke it."
		}
		cmd.RunE = func(cmd *cobra.Command, args []string) error {
			switch cmd.Name() {
			case "bash":
				return root.GenBashCompletionV2(cmd.OutOrStdout(), true)
			case "zsh":
				return root.GenZshCompletion(cmd.OutOrStdout())
			case "fish":
				return root.GenFishCompletion(cmd.OutOrStdout(), true)
			default:
				return root.GenPowerShellCompletionWithDesc(cmd.OutOrStdout())
			}
		}
		completion.AddCommand(cmd)
	}
	root.AddCommand(completion)
}
