package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/fasmide/tunnel/internal/server"
)

func writeAdminResult(out io.Writer, c config, result server.AdminResult) error {
	if c.jsonOutput {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(result); err != nil {
			return fmt.Errorf("encode admin result: %w", err)
		}
		return nil
	}
	if c.request.Command == "invites" {
		return writeInvites(out, result.Invites)
	}
	var message string
	switch c.request.Command {
	case "approve":
		message = "Approved invite " + c.request.ID + "."
	case "reject":
		message = "Rejected invite " + c.request.ID + "."
	case "revoke":
		message = "Revoked identity " + c.request.ID + "."
	case "set-routes":
		if len(c.request.Routes) == 0 {
			message = "Cleared routes for identity " + c.request.ID + "."
		} else {
			message = "Updated routes for identity " + c.request.ID + ": " + strings.Join(c.request.Routes, ", ")
		}
	}
	if _, err := fmt.Fprintln(out, message); err != nil {
		return fmt.Errorf("write admin confirmation: %w", err)
	}
	return nil
}

func writeInvites(out io.Writer, invites []server.Invite) error {
	if len(invites) == 0 {
		if _, err := fmt.Fprintln(out, "No access requests."); err != nil {
			return fmt.Errorf("write empty invites: %w", err)
		}
		return nil
	}
	table := tabwriter.NewWriter(out, 0, 8, 2, ' ', 0)
	if _, err := fmt.Fprintln(table, "INVITE ID\tSTATUS\tIDENTITY\tREQUESTED HOSTNAMES"); err != nil {
		return fmt.Errorf("write invites header: %w", err)
	}
	pending := false
	for _, invite := range invites {
		pending = pending || invite.Status == "pending"
		routes := strings.Join(invite.Join.Request.Routes, ", ")
		if routes == "" {
			routes = "-"
		}
		if _, err := fmt.Fprintf(table, "%s\t%s\t%s\t%s\n", invite.ID, invite.Status, shortIdentity(invite.Identity), routes); err != nil {
			return fmt.Errorf("write invite row: %w", err)
		}
	}
	if err := table.Flush(); err != nil {
		return fmt.Errorf("flush invites table: %w", err)
	}
	if pending {
		if _, err := fmt.Fprintln(out, "\nReview the requested hostnames, then approve or reject:\n  tunnelctl approve INVITE_ID\n  tunnelctl reject INVITE_ID"); err != nil {
			return fmt.Errorf("write invite guidance: %w", err)
		}
	}
	return nil
}
