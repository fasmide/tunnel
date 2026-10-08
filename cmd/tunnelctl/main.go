package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fasmide/tunnel"
	"github.com/fasmide/tunnel/internal/cli"
	"github.com/fasmide/tunnel/internal/server"
	"github.com/spf13/cobra"
)

type config struct {
	socket, server, serverName string
	replace                    bool
	all                        bool
	fullID                     bool
	jsonOutput                 bool
	request                    server.AdminRequest
}

func newCommand(c *config, action func(config) error) *cobra.Command {
	root := &cobra.Command{Use: "tunnelctl", Short: "Manage tunnel identities and routes",
		Long:    "Administer a running daemon through its local Unix socket.\nWith no subcommand, show routes. Obtain fingerprints locally for trusted distribution.",
		Example: "  tunnelctl invites\n  tunnelctl approve INVITE_ID\n  tunnelctl routes --all",
		Args:    cobra.NoArgs, SilenceUsage: true, SilenceErrors: true}
	flags := root.PersistentFlags()
	flags.StringVarP(&c.socket, "socket", "s", "/run/tunneld/admin.sock", "daemon admin Unix socket")
	flags.StringVar(&c.server, "server", "", "daemon QUIC hostname or host:port for fingerprint")
	flags.StringVar(&c.serverName, "server-name", "", "transport TLS DNS name override for fingerprint, e.g. when dialing an IP")
	flags.BoolVar(&c.jsonOutput, "json", false, "emit JSON output")
	execute := func(cmd *cobra.Command, args []string) error {
		name := cmd.Name()
		if cmd == root {
			name = "routes"
		}
		validated, err := validateConfig(*c, append([]string{name}, args...))
		if err != nil {
			return err
		}
		*c = validated
		return action(validated)
	}
	root.RunE = execute
	for _, spec := range []struct {
		use, short string
		args       cobra.PositionalArgs
	}{
		{"routes", "Show authorized routes and live clients", cobra.NoArgs},
		{"invites", "List access requests awaiting a decision", cobra.NoArgs},
		{"approve INVITE_ID", "Approve an access request", cobra.ExactArgs(1)},
		{"reject INVITE_ID", "Reject an access request", cobra.ExactArgs(1)},
		{"revoke IDENTITY_ID", "Revoke an identity and disconnect its clients", cobra.ExactArgs(1)},
		{"set-routes IDENTITY_ID [HOSTNAME...]", "Replace an identity's hostname grants (omit names to clear)", cobra.MinimumNArgs(1)},
		{"fingerprint", "Print the daemon CA fingerprint", cobra.NoArgs},
	} {
		child := &cobra.Command{Use: spec.use, Short: spec.short, Args: spec.args, RunE: execute}
		if child.Name() == "approve" {
			child.Flags().BoolVar(&c.replace, "replace", false, "revoke conflicting owners first")
		}
		if spec.use == "routes" {
			child.Flags().BoolVarP(&c.all, "all", "a", false, "include revoked identities")
			child.Flags().BoolVar(&c.fullID, "full-id", false, "show full identity values")
		}
		if spec.use == "fingerprint" {
			child.Long = "Print the local daemon's CA fingerprint, or fetch one with --server.\nA remotely fetched fingerprint is not verified: compare it through a trusted channel."
		}
		root.AddCommand(child)
	}
	cli.AddCompletion(root)
	cli.AddVersion(root)
	return root
}

//nolint:unused // Used by tests, which are excluded from linting.
func parse(args []string) (config, error) {
	var c config
	cmd := newCommand(&c, func(config) error { return nil })
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err != nil {
		return c, fmt.Errorf("parse tunnelctl command: %w", err)
	}
	return c, nil
}

func validateConfig(c config, remaining []string) (config, error) {
	if c.socket == "" {
		return c, fmt.Errorf("-s, --socket cannot be empty")
	}
	c.request = server.AdminRequest{Command: remaining[0], Routes: []string{}}
	switch remaining[0] {
	case "invites", "routes":
		if len(remaining) != 1 {
			return c, fmt.Errorf("unexpected arguments")
		}
	case "approve", "reject", "revoke":
		if len(remaining) != 2 {
			return c, fmt.Errorf("command requires an ID")
		}
		c.request.ID = remaining[1]
	case "set-routes":
		if len(remaining) < 2 {
			return c, fmt.Errorf("set-routes requires identity ID")
		}
		c.request.ID = remaining[1]
		c.request.Routes = remaining[2:]
	case "fingerprint":
		if len(remaining) != 1 {
			return c, fmt.Errorf("unexpected arguments")
		}
		if c.server != "" {
			var err error
			c.server, err = fingerprintServerAddress(c.server)
			if err != nil {
				return c, fmt.Errorf("--server: %w", err)
			}
		}
	default:
		return c, fmt.Errorf("unknown command %s", remaining[0])
	}
	return c, nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr, os.Stdin); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string, stdout, stderr *os.File, stdin io.Reader) error {
	var c config
	cmd := newCommand(&c, func(c config) error { return executeConfig(c, stdout, stderr, stdin) })
	cmd.SetArgs(args)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	cmd.SetIn(stdin)
	if err := cmd.Execute(); err != nil {
		return fmt.Errorf("tunnelctl: %w", err)
	}
	return nil
}

func executeConfig(c config, stdout, stderr *os.File, stdin io.Reader) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if c.request.Command == "fingerprint" {
		if c.server != "" {
			trust, err := tunnel.FetchTransportTrust(ctx, c.server, c.serverName)
			if err != nil {
				return fmt.Errorf("fetch transport trust: %w", err)
			}
			return writeFingerprint(stdout, trust.Fingerprint, c.jsonOutput)
		}
		result, err := server.AdminCall(ctx, c.socket, c.request)
		if err != nil {
			return fmt.Errorf("request daemon fingerprint: %w", err)
		}
		return writeFingerprint(stdout, result.Fingerprint, c.jsonOutput)
	}
	result, err := adminRun(ctx, c, stderr, stdin)
	if err != nil {
		return err
	}
	if c.request.Command == "routes" {
		routes := result.Routes
		if !c.all {
			filtered := routes[:0]
			for _, route := range routes {
				if !route.Revoked {
					filtered = append(filtered, route)
				}
			}
			routes = filtered
		}
		if c.jsonOutput {
			encoder := json.NewEncoder(stdout)
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(routes); err != nil {
				return fmt.Errorf("encode routes: %w", err)
			}
			return nil
		}
		if err := writeRoutes(stdout, routes, c.fullID); err != nil {
			return err
		}
		return nil
	}
	return writeAdminResult(stdout, c, result)
}

func writeFingerprint(out io.Writer, fingerprint string, jsonOutput bool) error {
	if jsonOutput {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(struct {
			Fingerprint string `json:"fingerprint"`
		}{Fingerprint: fingerprint}); err != nil {
			return fmt.Errorf("encode fingerprint: %w", err)
		}
		return nil
	}
	if _, err := fmt.Fprintln(out, fingerprint); err != nil {
		return fmt.Errorf("write fingerprint: %w", err)
	}
	return nil
}

func adminRun(ctx context.Context, c config, stderr *os.File, stdin io.Reader) (server.AdminResult, error) {
	result, err := server.AdminCall(ctx, c.socket, c.request)
	if err == nil {
		for _, warning := range result.Warnings {
			if _, writeErr := fmt.Fprintln(stderr, "WARNING:", warning); writeErr != nil {
				return result, fmt.Errorf("write warning: %w", writeErr)
			}
		}
		return result, nil
	}
	if c.request.Command != "approve" || !strings.Contains(err.Error(), " already owned by ") {
		return result, fmt.Errorf("admin request failed: %w", err)
	}
	conflictRoute, conflictID, ok := parseOwnerConflict(err.Error())
	if !ok {
		return result, fmt.Errorf("parse ownership conflict: %w", err)
	}
	if !c.replace && !canPrompt(stderr, stdin) {
		return result, fmt.Errorf("%w (rerun with --replace to revoke %s and approve invite %s)", err, conflictID, c.request.ID)
	}
	if c.replace {
		if _, writeErr := fmt.Fprintf(stderr, "Replacing %s owner %s before approving invite %s\n", conflictRoute, conflictID, c.request.ID); writeErr != nil {
			return result, fmt.Errorf("write replacement notice: %w", writeErr)
		}
	} else {
		if _, writeErr := fmt.Fprintf(stderr, "%s\nRevoke current owner %s and approve invite %s? [y/N] ", err.Error(), conflictID, c.request.ID); writeErr != nil {
			return result, fmt.Errorf("write approval prompt: %w", writeErr)
		}
		answer, readErr := readConfirmation(stdin)
		if readErr != nil {
			return result, readErr
		}
		if !answer {
			return result, errors.New("approval cancelled")
		}
	}
	if _, err = server.AdminCall(ctx, c.socket, server.AdminRequest{Command: "revoke", ID: conflictID}); err != nil {
		return result, fmt.Errorf("revoke conflicting owner: %w", err)
	}
	result, err = server.AdminCall(ctx, c.socket, c.request)
	if err != nil {
		return result, fmt.Errorf("approve invite after revoke: %w", err)
	}
	for _, warning := range result.Warnings {
		if _, writeErr := fmt.Fprintln(stderr, "WARNING:", warning); writeErr != nil {
			return result, fmt.Errorf("write warning: %w", writeErr)
		}
	}
	return result, nil
}

func parseOwnerConflict(message string) (route, identity string, ok bool) {
	const prefix = "route "
	const middle = " already owned by "
	if !strings.HasPrefix(message, prefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(message, prefix)
	before, after, found := strings.Cut(rest, middle)
	if !found || before == "" || after == "" {
		return "", "", false
	}
	return before, after, true
}

func fingerprintServerAddress(address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		switch {
		case strings.HasPrefix(address, "[") && strings.HasSuffix(address, "]"):
			host = strings.TrimSuffix(strings.TrimPrefix(address, "["), "]")
			ip, e := netip.ParseAddr(host)
			if e != nil || !ip.Is6() {
				return "", errors.New("invalid bracketed IPv6 address")
			}
		case !strings.Contains(address, ":"):
			host = address
		default:
			if _, e := netip.ParseAddr(address); e != nil {
				return "", fmt.Errorf("split server host/port: %w", err)
			}
			host = address
		}
		port = "7443"
	}
	if host == "" || strings.ContainsAny(host, " /\\\t\r\n?#[]") {
		return "", errors.New("invalid server host")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", errors.New("server port must be 1..65535")
	}
	return net.JoinHostPort(host, strconv.Itoa(n)), nil
}

func canPrompt(stderr *os.File, stdin io.Reader) bool {
	if stdin != os.Stdin {
		return false
	}
	if stderr == nil {
		return false
	}
	if info, err := stderr.Stat(); err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	return true
}

func readConfirmation(r io.Reader) (bool, error) {
	var answer string
	if _, err := fmt.Fscanln(r, &answer); err != nil {
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == "y" || answer == "yes", nil
}

func writeRoutes(w io.Writer, routes []server.RouteRecord, fullID bool) error {
	latestWidth := len("LATEST")
	smoothedWidth := len("SMOOTHED")
	minWidth := len("MIN")
	connWidth := len("CONNS")
	rxWidth := len("RX")
	txWidth := len("TX")
	for _, route := range routes {
		latestWidth = max(latestWidth, len(displayRTT(route.LatestRTT)))
		smoothedWidth = max(smoothedWidth, len(displayRTT(route.SmoothedRTT)))
		minWidth = max(minWidth, len(displayRTT(route.MinRTT)))
		connWidth = max(connWidth, len(strconv.FormatUint(route.Connections, 10)))
		rxWidth = max(rxWidth, len(humanBytes(route.RXBytes)))
		txWidth = max(txWidth, len(humanBytes(route.TXBytes)))
	}
	wtr := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	if _, err := fmt.Fprintf(wtr, "IDENTITY\tSTATUS\tAGE\t%s\t%s\t%s\t%s\t%s\t%s\tROUTE\n", rightAlign("LATEST", latestWidth), rightAlign("SMOOTHED", smoothedWidth), rightAlign("MIN", minWidth), rightAlign("CONNS", connWidth), rightAlign("RX", rxWidth), rightAlign("TX", txWidth)); err != nil {
		return fmt.Errorf("write routes header: %w", err)
	}
	for _, route := range routes {
		status, age := routeStatus(route.Online, route.ConnectedFor, route.OfflineFor, route.Revoked)
		name := route.Name
		if name == "" {
			name = "-"
		}
		identity := route.Identity
		if !fullID {
			identity = shortIdentity(identity)
		}
		if _, err := fmt.Fprintf(wtr, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", identity, status, age, rightAlign(displayRTT(route.LatestRTT), latestWidth), rightAlign(displayRTT(route.SmoothedRTT), smoothedWidth), rightAlign(displayRTT(route.MinRTT), minWidth), rightAlign(strconv.FormatUint(route.Connections, 10), connWidth), rightAlign(humanBytes(route.RXBytes), rxWidth), rightAlign(humanBytes(route.TXBytes), txWidth), name); err != nil {
			return fmt.Errorf("write routes row: %w", err)
		}
	}
	if err := wtr.Flush(); err != nil {
		return fmt.Errorf("flush routes table: %w", err)
	}
	return nil
}

func shortIdentity(id string) string {
	const keep = 8
	if len(id) <= keep*2+1 {
		return id
	}
	return id[:keep] + "…" + id[len(id)-keep:]
}

func rightAlign(text string, width int) string {
	if len(text) >= width {
		return text
	}
	return strings.Repeat(" ", width-len(text)) + text
}

func displayRTT(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for value := n / unit; value >= unit; value /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func routeStatus(online bool, connectedFor, offlineFor string, revoked bool) (status, age string) {
	if online {
		if connectedFor == "" {
			return "online", "-"
		}
		return "online", connectedFor
	}
	if offlineFor != "" {
		status = "offline"
		if revoked {
			status = "revoked"
		}
		return status, offlineFor
	}
	if revoked {
		return "revoked", "never connected"
	}
	return "offline", "never connected"
}
