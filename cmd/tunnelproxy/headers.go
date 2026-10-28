package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/spf13/pflag"
	"golang.org/x/net/http/httpguts"
)

// Register dynamic flags through pflag's name lookup so all Cobra entry points
// (including tests and completion) use the same parsing and missing-value rules.
func addHeaderFlags(flags *pflag.FlagSet, headers *http.Header) {
	registered := map[string]bool{}
	flags.SetNormalizeFunc(func(fs *pflag.FlagSet, name string) pflag.NormalizedName {
		if strings.HasPrefix(name, "header-") && !registered[name] {
			registered[name] = true // AddFlag also normalizes the name.
			fs.Var(&headerValue{headers: headers, name: strings.TrimPrefix(name, "header-")}, name, "enforce an upstream request header")
		}
		return pflag.NormalizedName(name)
	})
}

type headerValue struct {
	headers *http.Header
	name    string
}

func (v *headerValue) String() string { return v.headers.Get(v.name) }
func (*headerValue) Type() string     { return "string" }
func (v *headerValue) Set(value string) error {
	if err := validateHeader(v.name, value); err != nil {
		return err
	}
	if *v.headers == nil {
		*v.headers = make(http.Header)
	}
	v.headers.Set(v.name, value)
	return nil
}

func validateHeader(name, value string) error {
	if !httpguts.ValidHeaderFieldName(name) {
		return errors.New("invalid HTTP header name")
	}
	if !httpguts.ValidHeaderFieldValue(value) {
		return errors.New("invalid HTTP header value")
	}
	switch strings.ToLower(name) {
	case "host":
		if value == "" || !httpguts.ValidHostHeader(value) {
			return errors.New("Host requires a nonempty valid host value")
		}
	case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "content-length", "te", "trailer", "upgrade", "proxy-authenticate", "proxy-authorization":
		return fmt.Errorf("%s is managed by the HTTP transport and cannot be overridden", name)
	}
	return nil
}

// Apply after Rewrite's sanitization and forwarding headers, and after inbound
// authentication, so callers cannot replace enforced values or bypass auth.
func enforceHeaders(proxy *httputil.ReverseProxy, headers http.Header) {
	rewrite := proxy.Rewrite
	proxy.Rewrite = func(r *httputil.ProxyRequest) {
		rewrite(r)
		for name, values := range headers {
			if strings.EqualFold(name, "Host") {
				r.Out.Host = values[0]
			} else {
				r.Out.Header[name] = append([]string(nil), values...)
			}
		}
	}
}
