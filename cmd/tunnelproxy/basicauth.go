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

	"golang.org/x/crypto/bcrypt"
)

// basicAuth is immutable and shared by all requests for one invocation.
type basicAuth struct {
	username string
	anyUser  bool
	password [sha256.Size]byte
	hash     []byte
}

func parseBasicAuth(value string) (*basicAuth, error) {
	username, password, ok := strings.Cut(value, ":")
	if !ok || password == "" {
		return nil, errors.New("authentication requires user:password or user:bcrypt-hash with a nonempty password (an empty user accepts any username; a bare authentication flag generates a password)")
	}
	auth := &basicAuth{username: username, anyUser: username == ""}
	if strings.HasPrefix(password, "$2") {
		if _, err := bcrypt.Cost([]byte(password)); err != nil {
			return nil, errors.New("authentication contains an invalid bcrypt hash")
		}
		// Cost alone only parses the header. Validate the full encoded hash too.
		if len(password) != 60 || !(strings.HasPrefix(password, "$2a$") || strings.HasPrefix(password, "$2b$") || strings.HasPrefix(password, "$2y$")) {
			return nil, errors.New("authentication requires a complete $2a$, $2b$ or $2y$ bcrypt hash")
		}
		for _, c := range password[7:] {
			if !strings.ContainsRune("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", c) {
				return nil, errors.New("authentication contains an invalid bcrypt hash")
			}
		}
		auth.hash = []byte(password)
	} else {
		auth.password = sha256.Sum256([]byte(password))
	}
	return auth, nil
}

// basicAuthList accepts a request when any complete identity matches.
type basicAuthList []*basicAuth

func prepareBasicAuth(c config, out io.Writer) (basicAuthList, error) {
	flag, label, identities := "basicauth", "Basic authentication", c.basicAuth
	if c.cookieAuthEnabled {
		flag, label, identities = "cookieauth", "Cookie authentication", c.cookieAuth
	}
	if !c.basicAuthEnabled && !c.cookieAuthEnabled {
		return nil, nil
	}
	if c.mode == "raw" {
		_, err := fmt.Fprintf(out, "WARNING: --%s is NOT enforced in raw mode: TLS passes through unchanged. Configure authentication on the target service.\n", flag)
		return nil, err
	}
	if c.mode == "http" {
		if _, err := fmt.Fprintln(out, "WARNING: Authentication over plain HTTP exposes passwords and session cookies between the browser and public server; the encrypted QUIC tunnel does not protect that leg."); err != nil {
			return nil, err
		}
	}
	if len(identities) == 0 {
		identities = []string{""}
	}
	auths := make(basicAuthList, 0, len(identities))
	for i, value := range identities {
		auth, err := prepareAuthIdentity(value, flag, label, out)
		if err != nil {
			return nil, fmt.Errorf("%s identity %d: %w", label, i+1, err)
		}
		auths = append(auths, auth)
	}
	return auths, nil
}

func prepareAuthIdentity(value, flag, label string, out io.Writer) (*basicAuth, error) {
	if value != "" {
		auth, err := parseBasicAuth(value)
		if err != nil {
			return nil, err
		}
		if auth.hash == nil {
			_, password, _ := strings.Cut(value, ":")
			if err := printAuthBcryptHint(out, flag, auth.username, password); err != nil {
				return nil, err
			}
		}
		return auth, nil
	}
	var random [18]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, fmt.Errorf("generate authentication password: %w", err)
	}
	password := base64.RawURLEncoding.EncodeToString(random[:])
	auth := &basicAuth{anyUser: true, password: sha256.Sum256([]byte(password))}
	if _, err := fmt.Fprintf(out, "%s enabled; any username is accepted.\nPassword: %s\nWARNING: This password is not saved. Restarting tunnelproxy generates a new one. Anyone with access to these logs can read it.\n", label, password); err != nil {
		return nil, fmt.Errorf("write authentication password: %w", err)
	}
	if err := printAuthBcryptHint(out, flag, "", password); err != nil {
		return nil, err
	}
	return auth, nil
}

// Shell-quote the entire value: bcrypt contains dollar signs, and usernames
// may contain quotes. Never include the plaintext password in this hint.
func printBcryptHint(out io.Writer, username, password string) error {
	return printAuthBcryptHint(out, "basicauth", username, password)
}

func printAuthBcryptHint(out io.Writer, flag, username, password string) error {
	if len(password) > 72 {
		_, err := fmt.Fprintln(out, "TIP: bcrypt supports passwords up to 72 bytes; no bcrypt alternative was generated for this longer password.")
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("generate bcrypt alternative: %w", err)
	}
	value := strings.ReplaceAll(username+":"+string(hash), "'", "'\"'\"'")
	if _, err := fmt.Fprintf(out, "TIP: To reuse this password without configuring it in plaintext, use --%s='%s'\n", flag, value); err != nil {
		return fmt.Errorf("write bcrypt alternative: %w", err)
	}
	return nil
}

func (a *basicAuth) matches(username, password string) bool {
	userDigest := sha256.Sum256([]byte(username))
	expectedUser := sha256.Sum256([]byte(a.username))
	userOK := subtle.ConstantTimeCompare(userDigest[:], expectedUser[:]) == 1 || a.anyUser
	passwordOK := false
	if a.hash != nil {
		passwordOK = bcrypt.CompareHashAndPassword(a.hash, []byte(password)) == nil
	} else {
		digest := sha256.Sum256([]byte(password))
		passwordOK = subtle.ConstantTimeCompare(digest[:], a.password[:]) == 1
	}
	return userOK && passwordOK
}

func (a *basicAuth) wrap(next http.Handler) http.Handler {
	return basicAuthList{a}.wrap(next)
}

func (auths basicAuthList) wrap(next http.Handler) http.Handler {
	if len(auths) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		allowed := false
		if ok {
			// Check every entry rather than revealing which identity matched by
			// stopping early. Usernames and passwords must match the same entry.
			for _, auth := range auths {
				matched := auth.matches(username, password)
				allowed = allowed || matched
			}
		}
		if !allowed {
			w.Header().Set("WWW-Authenticate", `Basic realm="tunnelproxy", charset="UTF-8"`)
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		// Do not leak the shared secret into the application or its logs.
		r = r.Clone(r.Context())
		r.Header.Del("Authorization")
		next.ServeHTTP(w, r)
	})
}
