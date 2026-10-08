package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// bearerAuthList is immutable; only token digests survive preparation.
type bearerAuthList [][sha256.Size]byte

// RFC 6750 b64token: one or more token characters followed by optional '='.
func validBearerToken(token string) bool {
	if token == "" {
		return false
	}
	padding := false
	characters := 0
	for _, c := range token {
		if c == '=' {
			padding = true
			continue
		}
		if padding || !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~+/", c)) {
			return false
		}
		characters++
	}
	return characters > 0
}

func prepareBearerAuth(c config, out io.Writer) (bearerAuthList, error) {
	if !c.bearerAuthEnabled {
		return nil, nil
	}
	if c.mode == "raw" {
		return nil, errors.New("--bearerauth cannot be enforced in raw mode")
	}
	if c.mode == "http" {
		if _, err := fmt.Fprintln(out, "WARNING: Bearer authentication over plain HTTP exposes tokens between the caller and public server; the encrypted QUIC tunnel does not protect that leg."); err != nil {
			return nil, err
		}
	}
	tokens := c.bearerAuth
	if len(tokens) == 0 {
		tokens = []string{""}
	}
	auth := make(bearerAuthList, 0, len(tokens))
	for _, token := range tokens {
		if token == "" {
			var random [32]byte
			if _, err := rand.Read(random[:]); err != nil {
				return nil, fmt.Errorf("generate bearer token: %w", err)
			}
			token = base64.RawURLEncoding.EncodeToString(random[:])
			if _, err := fmt.Fprintf(out, "Bearer authentication enabled.\nToken: %s\nWARNING: This token is not saved. Restarting tunnelproxy generates a new one. Anyone with access to these logs can use it.\n", token); err != nil {
				return nil, fmt.Errorf("write bearer token: %w", err)
			}
		} else if !validBearerToken(token) {
			return nil, errors.New("invalid bearer token")
		}
		auth = append(auth, sha256.Sum256([]byte(token)))
	}
	return auth, nil
}

func (auth bearerAuthList) wrap(next http.Handler) http.Handler {
	if len(auth) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers := r.Header.Values("Authorization")
		token := ""
		if len(headers) == 1 {
			scheme, value, ok := strings.Cut(headers[0], " ")
			if ok && strings.EqualFold(scheme, "Bearer") {
				// The scheme is followed by one or more SP, not arbitrary whitespace.
				value = strings.TrimLeft(value, " ")
				if validBearerToken(value) {
					token = value
				}
			}
		}
		allowed := 0
		if token != "" {
			digest := sha256.Sum256([]byte(token))
			for _, expected := range auth {
				allowed |= subtle.ConstantTimeCompare(digest[:], expected[:])
			}
		}
		if allowed != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="tunnelproxy"`)
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		r = r.Clone(r.Context())
		r.Header.Del("Authorization")
		next.ServeHTTP(w, r)
	})
}
