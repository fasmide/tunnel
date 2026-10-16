package server

import "time"

// CleanupInvites durably expires abandoned requests and prunes old decisions.
// It does not mutate authorization or the authorization revision.
func (m *Manager) CleanupInvites() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cleanupInvitesLocked(time.Now().Unix())
}

func (m *Manager) cleanupInvitesLocked(now int64) error {
	if m.stateErr != nil {
		return m.stateErr
	}
	// Avoid cloning the entire authorization snapshot on every join/poll.
	changed := false
	for _, invite := range m.invites {
		if invite.Status == "pending" && now >= invite.ExpiresAt ||
			invite.Status != "pending" && now >= invite.FinishedAt+int64(InviteRetention/time.Second) {
			changed = true
			break
		}
	}
	if !changed {
		return nil
	}
	state := m.stateLocked()
	for id, invite := range state.Invites {
		if invite.Status == "pending" && now >= invite.ExpiresAt {
			invite.Status = "expired"
			invite.FinishedAt = invite.ExpiresAt
			state.Invites[id] = invite
		}
		if invite.Status != "pending" && now >= invite.FinishedAt+int64(InviteRetention/time.Second) {
			delete(state.Invites, id)
		}
	}
	if err := m.persistLocked(state); err != nil {
		return err
	}
	m.invites = state.Invites
	return nil
}
