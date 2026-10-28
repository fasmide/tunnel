package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/fasmide/tunnel/internal/names"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func userUnitArgs(cmd *cobra.Command, c config) ([]string, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("--install-user-unit requires Linux with systemd")
	}
	if !names.Valid(c.name) || len("tunnelproxy-"+c.name+".service") > 255 {
		return nil, errors.New("--name must be a lowercase DNS hostname fitting a systemd unit filename")
	}
	for _, values := range [][]string{c.basicAuth, c.cookieAuth, c.bearerAuth} {
		for _, value := range values {
			if value == "" {
				return nil, errors.New("--install-user-unit requires explicit authentication passwords or tokens; bare authentication flags would generate new credentials on every restart")
			}
		}
	}
	args := []string{c.command}
	var pathErr error
	cmd.Flags().Visit(func(flag *pflag.Flag) {
		if pathErr != nil {
			return
		}
		if flag.Name == "install-user-unit" || flag.Name == "state" {
			return
		}
		values := []string{flag.Value.String()}
		if slice, ok := flag.Value.(pflag.SliceValue); ok {
			values = slice.GetSlice()
		}
		for _, value := range values {
			switch flag.Name {
			case "root", "cert", "key", "clientcertauth-ca", "target-unix-socket":
				value, pathErr = filepath.Abs(value)
			}
			args = append(args, "--"+flag.Name+"="+value)
		}
	})
	if pathErr != nil {
		return nil, fmt.Errorf("resolve service path: %w", pathErr)
	}
	state, err := filepath.Abs(c.state)
	if err != nil {
		return nil, fmt.Errorf("resolve state path: %w", err)
	}
	args = append(args, "--state="+state)
	// file-serve defaults to the current directory; freeze that default too.
	if c.command == "file-serve" && !cmd.Flags().Changed("root") {
		root, err := filepath.Abs(c.root)
		if err != nil {
			return nil, err
		}
		args = append(args, "--root="+root)
	}
	return args, nil
}

// systemd uses C-style quoting, specifier expansion, and (for ExecStart only)
// dollar expansion. Shell quoting alone is not sufficient.
func unitQuote(value string, execArg bool) string {
	value = strings.ReplaceAll(value, "%", "%%")
	if execArg {
		value = strings.ReplaceAll(value, "$", "$$")
	}
	return strconv.Quote(value)
}

func writeNewPrivateFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func writeUserUnit(c config, configDir, executable, cwd string) (string, error) {
	unitName := "tunnelproxy-" + c.name + ".service"
	unitPath := filepath.Join(configDir, "systemd", "user", unitName)
	if _, err := os.Lstat(unitPath); err == nil {
		return "", fmt.Errorf("refusing to overwrite %s", unitPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(unitPath), 0700); err != nil {
		return "", err
	}
	command := []string{unitQuote(executable, true)}
	for _, arg := range c.unitArgs {
		command = append(command, unitQuote(arg, true))
	}
	unit := "[Unit]\nDescription=Tunnelproxy for " + c.name + "\n\n" +
		"[Service]\nType=simple\n" +
		"WorkingDirectory=" + unitQuote(cwd, false) + "\n" +
		"ExecStart=" + strings.Join(command, " ") + "\n" +
		"Restart=on-failure\nRestartSec=5s\nTimeoutStopSec=" + strconv.FormatInt(int64(c.drainTimeout/time.Second)+5, 10) + "s\n" +
		"UMask=0077\nNoNewPrivileges=yes\n\n[Install]\nWantedBy=default.target\n"
	if err := writeNewPrivateFile(unitPath, []byte(unit)); err != nil {
		return "", fmt.Errorf("write unit %s: %w", unitPath, err)
	}
	return unitPath, nil
}

func installUserUnit(c config, out io.Writer) error {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	configDir, err = filepath.Abs(configDir)
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	unitPath, err := writeUserUnit(c, configDir, executable, cwd)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Created user unit (0600): %s\nUses existing state: %s\nThe service has not been enabled or started. Keep the executable at %s.\n", unitPath, c.state, executable)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "systemctl", "--user", "daemon-reload").Run(); err != nil {
		_, _ = fmt.Fprintln(out, "WARNING: Could not reload the systemd user manager. Run: systemctl --user daemon-reload")
	} else {
		_, _ = fmt.Fprintln(out, "Reloaded the systemd user manager.")
	}
	_, err = fmt.Fprintf(out, "\nEnable and start:\n  systemctl --user enable --now %s\nCheck status:\n  systemctl --user status %s\n\nFor startup at boot and operation after logout, user lingering must be enabled.\nCheck:  loginctl show-user \"$(id -un)\" -p Linger\nEnable: loginctl enable-linger \"$(id -un)\"\nEnabling lingering may require administrator authorization.\n", filepath.Base(unitPath), filepath.Base(unitPath))
	return err
}
