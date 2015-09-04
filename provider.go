package oauthmw

import (
	"crypto/md5"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/ymichael/sessions"
	"github.com/zenazn/goji/web"
	"golang.org/x/oauth2"
)

const (
	// Default key for oauthmw session store
	DefaultSessionKey = "oauthmw"

	DefaultPagePrefix     = "oauth-"
	DefaultReturnName     = "login"
	DefaultLogoutName     = "logout"
	DefaultRedirectPrefix = "redirect-"

	// Default lifetime of a session token
	DefaultSessionLifetime = 12 * time.Hour

	// Default max number of states allowed in each user's session storage
	DefaultMaxStates = 128 // FIXME -- implement this correctly ...
)

// Provider configuration.
type Provider struct {
	// Secrets for oauth2 transfer state (passed to gorilla/securecookie)
	Secret      string
	BlockSecret string

	// oauth2 configs
	Configs map[string]*oauth2.Config

	// Session management object used to retrieve/set user's session
	Session *sessions.SessionOptions

	// Secured path
	Path string

	// Session storage configuration
	// SessionKey should be unique per path
	SessionKey      string
	SessionLifetime time.Duration

	// Token lifetime after redemption
	TokenLifetime time.Duration

	// Middleware path configuration
	PagePrefix     string
	ReturnName     string
	LogoutName     string
	RedirectPrefix string

	// Optional to specify, but when provided then this is the order that
	// providers are listed in the template to users.
	ConfigsOrder []string // FIXME -- not working as wanted

	// Function used for templates
	TemplateFn func(map[string]string, http.ResponseWriter, *http.Request)

	// Goji stuff
	SubRouter bool

	// Should states be cleaned up if they are past expiration
	CleanupStates bool
	MaxStates     int
}

// Encode oauth2 transfer state for a named provider.
func (p Provider) EncodeState(sessionId, provName, resource string) (string, error) {
	sc := securecookie.New([]byte(p.Secret), []byte(p.BlockSecret))
	sc.MaxAge(int(p.SessionLifetime))

	state := map[string]string{
		"sid":      sessionId,
		"provider": provName,
		"resource": resource,
	}

	return sc.Encode(p.SessionKey, state)
}

// Decode oauth2 transfer state encoded with EncodeState.
func (p Provider) DecodeState(data string) (map[string]string, error) {
	sc := securecookie.New([]byte(p.Secret), []byte(p.BlockSecret))
	sc.MaxAge(int(p.SessionLifetime))

	state := make(map[string]string)
	err := sc.Decode(p.SessionKey, data, &state)

	return state, err
}

// Check (and set) defaults on Provider if not provided at object construction.
func (p *Provider) checkDefaults() {
	if p.Secret == "" {
		panic(errors.New("oauthmw provider Secret cannot be empty string"))
	}

	if p.BlockSecret == "" {
		panic(errors.New("oauthmw provider BlockSecret cannot be empty string"))
	}

	if p.Path == "" {
		panic(errors.New("oauthmw provider Path cannot be empty string"))
	}

	if p.PagePrefix == "" {
		p.PagePrefix = "/" + DefaultPagePrefix
	}

	if p.ReturnName == "" {
		p.ReturnName = p.PagePrefix + DefaultReturnName
	}

	if p.LogoutName == "" {
		p.LogoutName = p.PagePrefix + DefaultLogoutName
	}

	if p.RedirectPrefix == "" {
		p.RedirectPrefix = p.PagePrefix + DefaultRedirectPrefix
	}

	if p.SessionKey == "" {
		h := md5.Sum([]byte(p.Path))
		p.SessionKey = fmt.Sprintf("%s%x", DefaultSessionKey, h[:3])
	}

	if p.SessionLifetime == 0 {
		p.SessionLifetime = DefaultSessionLifetime
	}

	if p.TemplateFn == nil {
		p.TemplateFn = defaultTemplateFn
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

// Build login provider.
func (p Provider) buildLogin(checkFn func() bool, required bool) func(*web.C, http.Handler) http.Handler {
	prov := &p
	prov.checkDefaults()

	return func(c *web.C, h http.Handler) http.Handler {
		if c.Env == nil {
			c.Env = make(map[interface{}]interface{})
		}

		if c.URLParams == nil {
			c.URLParams = make(map[string]string)
		}

		return login{
			provider: prov,
			check:    checkFn,
			required: required,
			c:        c,
			h:        h,
		}
	}
}

// Provide simple login
func (p Provider) Login(checkFn func() bool) func(*web.C, http.Handler) http.Handler {
	return p.buildLogin(checkFn, false)
}

// Require user to be logged in to oauth provider.
func (p Provider) RequireLogin(checkFn func() bool) func(*web.C, http.Handler) http.Handler {
	return p.buildLogin(checkFn, true)
}
