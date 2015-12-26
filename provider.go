// Package oauthmw provides an OAuth2.0 login flow middleware for Goji v2.
package oauthmw

import (
	"crypto/md5"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"goji.io"

	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2"
)

const (
	// DefaultSessionKey is the default key used for the oauthmw session store.
	//
	// Override with Provider.SessionKey
	DefaultSessionKey = "oauthmw"

	// DefaultPagePrefix is the default page prefix used for oauthmw pages.
	//
	// Override with Provider.PagePrefix
	DefaultPagePrefix = "oauth-"

	// DefaultRedirectPrefix is the default prefix used for redirects to
	// OAuth2.0 pages.
	//
	// Override with Provider.
	DefaultRedirectPrefix = "redirect-"

	// DefaultReturnName is the default path name used for return (login).
	//
	// Override with Provider.ReturnName
	DefaultReturnName = "login"

	// DefaultLogoutName is the default path name used for logout.
	//
	// Please note this is not yet implemented.
	//
	// Override with Provider.LogoutName
	DefaultLogoutName = "logout"

	// DefaultStateLifetime is the default lifetime (ttl) for an oauth2
	// transfer state.
	//
	// Override with Provider.StateLifetime
	DefaultStateLifetime = 12 * time.Hour

	// DefaultMaxStates is the maximum number of states allowed in the session
	// storage before a cleanup is triggered.
	//
	// Override with Provider.MaxStates
	DefaultMaxStates = 128
)

// Provider configuration.
type Provider struct {
	// Secret for oauth2 transfer state (passed to gorilla/securecookie).
	//
	// Must not be empty.
	Secret []byte

	// BlockSecret for oauth2 transfer state (passed to gorilla/securecookie).
	//
	// Must not be empty.
	BlockSecret []byte

	// Path that is being secured.
	//
	// Used for redirects. Must not be empty.
	Path string

	// Configs for oauth2
	Configs map[string]*oauth2.Config

	// SessionKey is the key used to retrieve the oauthmw states from the
	// session.
	//
	// Should be unique per path.
	//
	// If empty, then this is set as the DefaultSessionKey plus the first 6
	// characters of the md5 hash of the Provider.Path.
	SessionKey string

	// StateLifetime is the lifetime (ttl) of an oauth2 transfer state.
	StateLifetime time.Duration

	// TokenLifetime is maximum allowed token lifetime (ttl) after redemption.
	//
	// This is useful if you want to force an expiration for redeemed oauth2
	// tokens.
	TokenLifetime time.Duration

	// PagePrefix is the prefix used to check all page requests (default: "oauth-")
	//
	// All redirect/return/logout paths must start with this prefix.
	PagePrefix string

	// RedirectPrefix is the optional path prefix used for redirects (default: "redirect-").
	RedirectPrefix string

	// ReturnName is the path name used for returns (default: "login").
	ReturnName string

	// LogoutName is the path name used for logout (default: "logout").
	//
	// Please note that logout is not yet implemented.
	LogoutName string

	// ConfigsOrder is an optional for the configs processing on the protected
	// page template.
	//
	// Optional to specify, but when provided then this is the order that
	// providers are listed in the template to users.
	ConfigsOrder []string // FIXME -- not implemented properly

	// TemplateFn is the function used for generating template on protected
	// page when there is no valid oauth2.Token in the session.
	TemplateFn func(map[string]string, http.ResponseWriter, *http.Request)

	// ErrorFn is the function called when an error is produced.
	ErrorFn func(int, string, http.ResponseWriter, *http.Request)

	// SubRouter toggles SubRouter path handling for goji subrouter middleware.
	//SubRouter bool

	// CleanupStates when true causes simple cleanup to happen on the oauth2
	// transfer states stored in the session that are already expired.
	CleanupStates bool

	// MaxStates is the number of states allowed before cleanup is triggered.
	//
	// Set to -1 for unlimited states.
	MaxStates int
}

// EncodeState returns an encoded (and secure) oauth2 transfer state for the
// provided session id, named provider, and specified resource.
func (p Provider) EncodeState(sessionID, provName, resource string) (string, error) {
	sc := securecookie.New(p.Secret, p.BlockSecret)
	sc.MaxAge(int(p.StateLifetime))

	state := map[string]string{
		"sid":      sessionID,
		"provider": provName,
		"resource": resource,
	}

	return sc.Encode(p.SessionKey, state)
}

// DecodeState decodes the oauth2 transfer state encoded with EncodeState.
func (p Provider) DecodeState(data string) (map[string]string, error) {
	sc := securecookie.New(p.Secret, p.BlockSecret)
	sc.MaxAge(int(p.StateLifetime))

	state := make(map[string]string)
	err := sc.Decode(p.SessionKey, data, &state)

	return state, err
}

// checkDefaults checks (and sets) defaults on Provider
func (p *Provider) checkDefaults() {
	if len(p.Secret) < 1 {
		panic(errors.New("oauthmw provider Secret cannot be empty"))
	}

	if len(p.BlockSecret) < 1 {
		panic(errors.New("oauthmw provider BlockSecret cannot be empty"))
	}

	if p.Path == "" {
		panic(errors.New("oauthmw provider Path cannot be empty string"))
	}

	if p.SessionKey == "" {
		h := md5.Sum([]byte(p.Path))
		p.SessionKey = fmt.Sprintf("%s%x", DefaultSessionKey, h[:3])
	}

	if p.PagePrefix == "" {
		p.PagePrefix = "/" + DefaultPagePrefix
	}

	if p.RedirectPrefix == "" {
		p.RedirectPrefix = p.PagePrefix + DefaultRedirectPrefix
	}

	if p.ReturnName == "" {
		p.ReturnName = p.PagePrefix + DefaultReturnName
	}

	if p.LogoutName == "" {
		p.LogoutName = p.PagePrefix + DefaultLogoutName
	}

	if p.StateLifetime == 0 {
		p.StateLifetime = DefaultStateLifetime
	}

	if p.TemplateFn == nil {
		p.TemplateFn = defaultTemplateFn
	}

	if p.ErrorFn == nil {
		p.ErrorFn = defaultErrorFn
	}

	if p.MaxStates == 0 {
		p.MaxStates = DefaultMaxStates
	}

	// fill ConfigsOrder with keys in alphabetical order if not provided
	if len(p.ConfigsOrder) < 1 {
		p.ConfigsOrder = make([]string, len(p.Configs))
		i := 0
		for k := range p.Configs {
			p.ConfigsOrder[i] = k
			i++
		}
		sort.Strings(p.ConfigsOrder)
	}
}

// buildLogin creates the actual login provider.
func (p Provider) buildLogin(checkFn CheckFn, required bool) func(goji.Handler) goji.Handler {
	prov := &p
	prov.checkDefaults()

	return func(h goji.Handler) goji.Handler {
		return login{
			provider: prov,
			required: required,
			checkFn:  checkFn,
			h:        h,
		}
	}
}

// Login provides a goji.Handler that handles oauth2 login flows, but does
// not require there to be a login.
//
// NOTE: Any mux using this middleware WILL be visible to an unauthenticated
// user.
func (p Provider) Login(checkFn CheckFn) func(goji.Handler) goji.Handler {
	return p.buildLogin(checkFn, false)
}

// RequireLogin provides goji.Handler that handles oauth2 login flows,
// requiring that there be a valid login prior to acessing a protected
// resource.
func (p Provider) RequireLogin(checkFn CheckFn) func(goji.Handler) goji.Handler {
	return p.buildLogin(checkFn, true)
}
