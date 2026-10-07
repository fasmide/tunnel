package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const authLoginPath = "/_tunnelproxy/auth/login"
const authLogoutPath = "/_tunnelproxy/auth/logout"

// Tokens are signed, not encrypted. No password or password hash is included.
type authToken struct {
	Version int    `json:"v"`
	Kind    string `json:"k"`
	Host    string `json:"h"`
	User    string `json:"u,omitempty"`
	Issued  int64  `json:"iat"`
	Expires int64  `json:"exp"`
	Nonce   string `json:"n,omitempty"`
}

type cookieAuth struct {
	key        [32]byte
	identities basicAuthList
	duration   time.Duration
	secure     bool
	now        func() time.Time
	loginSlots chan struct{}
}

func newCookieAuth(identities basicAuthList, duration time.Duration, secure bool) (*cookieAuth, error) {
	a := &cookieAuth{identities: identities, duration: duration, secure: secure, now: time.Now, loginSlots: make(chan struct{}, 8)}
	if _, err := rand.Read(a.key[:]); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *cookieAuth) cookieName() string {
	if a.secure {
		return "__Host-tunnelproxy-session"
	}
	return "tunnelproxy-session"
}
func (a *cookieAuth) csrfName() string { return a.cookieName() + "-csrf" }
func (a *cookieAuth) cookie(name, value string, lifetime time.Duration) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode, MaxAge: int(lifetime / time.Second), Expires: a.now().Add(lifetime)}
}
func (a *cookieAuth) sign(kind, host, user, nonce string, duration time.Duration) string {
	payload, _ := json.Marshal(authToken{Version: 1, Kind: kind, Host: host, User: user, Nonce: nonce, Issued: a.now().Unix(), Expires: a.now().Add(duration).Unix()})
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, a.key[:])
	_, _ = mac.Write([]byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func (a *cookieAuth) valid(value, kind, host string) bool {
	if len(value) > 4096 {
		return false
	}
	payload, signature, ok := strings.Cut(value, ".")
	if !ok {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, a.key[:])
	_, _ = mac.Write([]byte(payload))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return false
	}
	var token authToken
	if json.Unmarshal(decoded, &token) != nil {
		return false
	}
	now := a.now().Unix()
	return token.Version == 1 && token.Kind == kind && token.Host == host && token.Issued <= now && token.Expires > now && token.Expires > token.Issued
}

func safeReturnURL(value string) string {
	u, err := url.Parse(value)
	if err != nil || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || strings.ContainsAny(value, "\\\r\n") || strings.HasPrefix(u.Path, "//") || strings.ContainsAny(u.Path, "\\\r\n") || u.IsAbs() || u.Host != "" || strings.HasPrefix(u.Path, "/_tunnelproxy/auth/") {
		return "/"
	}
	return u.RequestURI()
}

var signInPage = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in · tunnelproxy</title>
<style>body{font:16px system-ui;background:#f4f5f7;color:#202530;margin:0}main{max-width:360px;margin:10vh auto;padding:2rem;background:white;border-radius:12px}label{display:block;margin-top:1rem}input{box-sizing:border-box;width:100%;padding:.6rem;margin-top:.3rem}button{margin-top:1.5rem;padding:.7rem 1rem}p{line-height:1.5}.error{color:#a21b1b}</style></head>
<body><main><h1>Sign in</h1><p>Sign in to access this development site.</p>{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
<form method="post" action="/_tunnelproxy/auth/login"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="return" value="{{.Return}}">
<label>Username<input name="username" autocomplete="username" maxlength="256"></label><label>Password<input type="password" name="password" autocomplete="current-password" required maxlength="4096"></label><button type="submit">Sign in</button></form></main></body></html>`))

var signOutPage = template.Must(template.New("logout").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign out · tunnelproxy</title></head><body><h1>Sign out</h1><form method="post" action="/_tunnelproxy/auth/logout"><input type="hidden" name="csrf" value="{{.}}"><button type="submit">Sign out</button></form></body></html>`))

func authPageHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Firefox can send Origin: null on form POSTs under no-referrer.
	// Preserve same-origin provenance without leaking URLs to other sites.
	w.Header().Set("Referrer-Policy", "same-origin")
}

// Reuse a valid browser token so opening another auth page does not invalidate
// forms in existing tabs. Do not refresh its cookie lifetime past token expiry.
func (a *cookieAuth) formToken(w http.ResponseWriter, r *http.Request) (string, error) {
	if cookie, err := r.Cookie(a.csrfName()); err == nil && a.valid(cookie.Value, "csrf", r.Host) {
		return cookie.Value, nil
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	csrf := a.sign("csrf", r.Host, "", base64.RawURLEncoding.EncodeToString(nonce[:]), 15*time.Minute)
	http.SetCookie(w, a.cookie(a.csrfName(), csrf, 15*time.Minute))
	return csrf, nil
}

func (a *cookieAuth) showLogin(w http.ResponseWriter, r *http.Request, returnURL, message string, status int) {
	csrf, err := a.formToken(w, r)
	if err != nil {
		http.Error(w, "Unable to prepare sign-in", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = signInPage.Execute(w, struct{ CSRF, Return, Error string }{csrf, safeReturnURL(returnURL), message})
}
func (a *cookieAuth) csrfOK(r *http.Request) bool {
	scheme := "http"
	if a.secure {
		scheme = "https"
	}
	origin, site := r.Header.Get("Origin"), r.Header.Get("Sec-Fetch-Site")
	if origin == "null" {
		// Previously served no-referrer pages may still submit an opaque Origin.
		// Only allow that with browser-provided same-origin Fetch Metadata;
		// the signed double-submit token below remains mandatory.
		if site != "same-origin" {
			return false
		}
	} else if origin != "" && origin != scheme+"://"+r.Host {
		return false
	}
	if site != "" && site != "same-origin" && site != "none" {
		return false
	}
	cookie, err := r.Cookie(a.csrfName())
	form := r.PostForm.Get("csrf")
	return err == nil && hmac.Equal([]byte(cookie.Value), []byte(form)) && a.valid(form, "csrf", r.Host)
}
func (a *cookieAuth) clearCookie(w http.ResponseWriter, name string) {
	c := a.cookie(name, "", -time.Hour)
	c.MaxAge = -1
	http.SetCookie(w, c)
}
func (a *cookieAuth) login(w http.ResponseWriter, r *http.Request) {
	authPageHeaders(w)
	if r.Method == http.MethodGet {
		a.showLogin(w, r, r.URL.Query().Get("return"), "", http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", 405)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if r.ParseForm() != nil {
		http.Error(w, "Invalid sign-in form", 400)
		return
	}
	if !a.csrfOK(r) {
		http.Error(w, "Invalid sign-in request; reload the sign-in page", 403)
		return
	}
	select {
	case a.loginSlots <- struct{}{}:
		defer func() { <-a.loginSlots }()
	default:
		w.Header().Set("Retry-After", "1")
		http.Error(w, "Sign-in busy; try again", 429)
		return
	}
	user, password := r.PostForm.Get("username"), r.PostForm.Get("password")
	allowed := false
	if len(user) <= 256 && len(password) <= 4096 {
		for _, identity := range a.identities {
			matched := identity.matches(user, password)
			allowed = allowed || matched
		}
	}
	if !allowed {
		a.showLogin(w, r, r.PostForm.Get("return"), "Incorrect username or password.", 401)
		return
	}
	token := a.sign("session", r.Host, user, "", a.duration)
	if len(token) > 3800 {
		http.Error(w, "Invalid sign-in identity", 400)
		return
	}
	http.SetCookie(w, a.cookie(a.cookieName(), token, a.duration))
	// Keep the CSRF token for a subsequent logout POST. It expires after 15m;
	// visiting the login page obtains a fresh token without ending the session.
	http.Redirect(w, r, safeReturnURL(r.PostForm.Get("return")), http.StatusSeeOther)
}
func (a *cookieAuth) logout(w http.ResponseWriter, r *http.Request) {
	authPageHeaders(w)
	if r.Method == http.MethodGet {
		csrf, err := a.formToken(w, r)
		if err != nil {
			http.Error(w, "Unable to prepare sign-out", 500)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = signOutPage.Execute(w, csrf)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", 405)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if r.ParseForm() != nil {
		http.Error(w, "Invalid logout form", 400)
		return
	}
	if !a.csrfOK(r) {
		http.Error(w, "Invalid logout request", 403)
		return
	}
	a.clearCookie(w, a.cookieName())
	a.clearCookie(w, a.csrfName())
	http.Redirect(w, r, authLoginPath, http.StatusSeeOther)
}
func (a *cookieAuth) reservedCookie(name string) bool {
	return name == a.cookieName() || name == a.csrfName()
}
func (a *cookieAuth) filterResponse(r *http.Response) {
	values := r.Header.Values("Set-Cookie")
	r.Header.Del("Set-Cookie")
	for _, value := range values {
		// Check the name even if later attributes are malformed: browsers can
		// be more permissive than ParseSetCookie.
		name, _, _ := strings.Cut(value, "=")
		if a.reservedCookie(strings.TrimSpace(name)) {
			continue
		}
		r.Header.Add("Set-Cookie", value)
	}
}
func (a *cookieAuth) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case authLoginPath:
			a.login(w, r)
			return
		case authLogoutPath:
			a.logout(w, r)
			return
		}
		cookie, err := r.Cookie(a.cookieName())
		if err != nil || !a.valid(cookie.Value, "session", r.Host) {
			w.Header().Set("Cache-Control", "no-store")
			if err == nil {
				a.clearCookie(w, a.cookieName())
			}
			if (r.Method == http.MethodGet || r.Method == http.MethodHead) && strings.Contains(r.Header.Get("Accept"), "text/html") && r.Header.Get("Upgrade") == "" {
				http.Redirect(w, r, authLoginPath+"?return="+url.QueryEscape(safeReturnURL(r.URL.RequestURI())), http.StatusSeeOther)
			} else {
				http.Error(w, "Sign in at "+authLoginPath, http.StatusUnauthorized)
			}
			return
		}
		r = r.Clone(r.Context())
		// Preserve application cookies; never forward our session or CSRF tokens.
		cookies := r.Cookies()
		r.Header.Del("Cookie")
		for _, c := range cookies {
			if !a.reservedCookie(c.Name) {
				r.AddCookie(c)
			}
		}
		next.ServeHTTP(w, r)
	})
}
