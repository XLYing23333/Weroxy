package weroxy

import (
	"crypto/hmac"

	wp "weroxy/server/internal/protocol/weroxy"
)

// Lookups use only the bounded in-memory registry. The public ID is never an
// authenticator; final-key proof and a fresh registry check are mandatory.
func (s *Service) lookupCredential(id []byte) (Device, bool) {
	if len(id) != 32 {
		return Device{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.devices {
		if !d.Revoked && !d.Paused && hmac.Equal(id, d.Credential.ID[:]) && d.Credential.PSK != [32]byte{} {
			return d, true
		}
	}
	return Device{}, false
}
func (s *Service) confirmCredential(authenticated Device, uid string) (Device, byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.confirmCredentialLocked(authenticated, uid)
}
func (s *Service) confirmCredentialLocked(authenticated Device, uid string) (Device, byte) {
	for _, d := range s.devices {
		if d.ID == authenticated.ID && d.UID == authenticated.UID && hmac.Equal(d.Credential.PSK[:], authenticated.Credential.PSK[:]) && (uid == "" || uid == d.UID) {
			if d.Revoked || d.Paused {
				return Device{}, wp.CodeRevoked
			}
			return d, 0
		}
	}
	return Device{}, wp.CodeAuth
}
