package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestCompletionDoesNotRunApplication(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		t.Run(shell, func(t *testing.T) {
			called := false
			root := &cobra.Command{Use: "testtool", RunE: func(*cobra.Command, []string) error { called = true; return nil }}
			AddCompletion(root)
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetArgs([]string{"completion", shell})
			if err := root.Execute(); err != nil {
				t.Fatal(err)
			}
			if called || !strings.Contains(out.String(), "testtool") {
				t.Fatalf("called=%v output=%q", called, out.String())
			}
		})
	}
}
