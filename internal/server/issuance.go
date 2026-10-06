package server

import (
	"encoding/base64"
	"time"

	"github.com/fasmide/tunnel/internal/transportpki"
	"github.com/fasmide/tunnel/internal/wire"
)

func (m *Manager) issueCertificate(id uint64, r wire.IssueCertificate, issuer *transportpki.Authority) wire.CertificateResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := wire.CertificateResult{Envelope: wire.Envelope{Type: "CertificateResult", ID: r.ID}, Name: r.Name, Chain: []string{}}
	fail := func(code, message string) wire.CertificateResult {
		result.Code = code
		result.Error = message
		return result
	}
	s := m.sessions[id]
	if s == nil {
		return fail("not_authorized", "session no longer live")
	}
	g, ok := m.grants[s.identity]
	if m.stateErr != nil || s.restricted || !ok || g.revoked || !ValidName(r.Name) || m.ownerLocked(r.Name) != s.identity {
		return fail("not_authorized", "name not owned by this approved identity")
	}
	if issuer == nil {
		return fail("unavailable", "daemon has no private signing CA")
	}
	// Per-identity rate across all sessions, not a bypassable per-connection cap.
	now := time.Now()
	if m.issuance == nil {
		m.issuance = map[string]joinRate{}
	}
	for identity, rate := range m.issuance {
		if now.Sub(rate.window) >= time.Minute {
			delete(m.issuance, identity)
		}
	}
	rate := m.issuance[s.identity]
	if now.Sub(m.globalIssuance.window) >= time.Minute {
		m.globalIssuance = joinRate{window: now}
	}
	if rate.count >= 30 || m.globalIssuance.count >= 300 || len(m.issuance) >= 4096 && rate.count == 0 {
		return fail("rate_limited", "private issuance limit reached (30/minute/identity, 300/minute globally)")
	}
	if rate.count == 0 {
		rate.window = now
	}
	rate.count++
	m.issuance[s.identity] = rate
	m.globalIssuance.count++
	der, err := base64.StdEncoding.Strict().DecodeString(r.CSR)
	if err != nil || base64.StdEncoding.EncodeToString(der) != r.CSR {
		return fail("invalid_request", "invalid CSR base64")
	}
	// Hold manager lock through signing so revocation/ownership edits cannot
	// return before an in-flight authorized issuance decision completes.
	chain, err := issuer.Issue(r.Name, der, now)
	if err != nil {
		return fail("invalid_request", err.Error())
	}
	for _, cert := range chain {
		result.Chain = append(result.Chain, base64.StdEncoding.EncodeToString(cert))
	}
	result.Code = "ok"
	return result
}
