package oauthmw

import (
	"crypto/md5"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zenazn/goji/web"
	"golang.org/x/oauth2"
)

var oauth2Context = oauth2.NoContext

// A CheckFn is passed a provider name, the original provider config, and the
// redeemed token after a successful OAuth2.0 exchange.
//
// CheckFn should return a redirect URL (if any) and whether or not to allow
// the login.
type CheckFn func(string, *oauth2.Config, *oauth2.Token) (string, bool)

// Login
type login struct {
	// provider configuration
	provider *Provider

	// whether or not a valid login is required
	required bool

	// check function after exchange
	checkFn CheckFn

	// web context
	c *web.C

	// the protected handler
	h http.Handler
}

// sessionStore returns the oauthmw session store.
func (l login) sessionStore() *Store {
	// grab session from context
	sess := l.provider.Session.GetSessionObject(l.c)

	// get store from session
	obj, ok := sess[l.provider.SessionKey]
	if ok {
		store, ok := obj.(Store)
		if !ok {
			// this shouldn't ever happen ...
			log.Println("CORRUPTED/MALFORMED SESSION STORAGE. OVERWRITING")
			store = Store{
				Provider: "",
				Token:    &oauth2.Token{},
				States:   make(map[string]StoreState),
			}

			sess[l.provider.SessionKey] = store
			return &store
		}

		return &store
	}

	// create new store in session and return
	store := Store{
		Provider: "",
		Token:    &oauth2.Token{},
		States:   make(map[string]StoreState),
	}
	sess[l.provider.SessionKey] = store
	return &store
}

// addState adds a state to session store.
func (l login) addState(provName, state string) {
	sess := l.sessionStore()

	key := fmt.Sprintf("%x", md5.Sum([]byte(state)))
	sess.States[key] = StoreState{
		Provider:   provName,
		Expiration: time.Now().Add(l.provider.StateLifetime),
		Redeemed:   false,
	}
}

// getSessionID returns the session id.
func (l login) getSessionID() string {
	sid := l.provider.Session.GetSessionId(l.c)
	return fmt.Sprintf("%x", md5.Sum([]byte(sid)))
}

// getToken returns the stored token from session.
//
// Returns the token, expired, and ok state.
func (l login) getToken() (*oauth2.Token, bool, bool) {
	// grab session object
	sess := l.sessionStore()

	// if token not present
	if sess.Token == nil {
		return nil, false, false
	}

	// determine if token is expired
	if !sess.Token.Expiry.IsZero() && time.Now().After(sess.Token.Expiry) {
		return sess.Token, true, true
	}

	return sess.Token, false, true
}

// doRedirect handles oauthmw redirects.
//
// Will validate passed state, and adds it to the session store.
func (l login) doRedirect(provName string, stateDec map[string]string, res http.ResponseWriter, req *http.Request) {
	prov, ok := l.provider.Configs[provName]
	if !ok {
		l.provider.ErrorFn(500, "invalid provider", res, req)
		return
	}

	// verify state belongs to this session
	if l.getSessionID() != stateDec["sid"] {
		l.provider.ErrorFn(500, "forged sid in redirect", res, req)
		return
	}

	// verify it matches provider
	if provName != stateDec["provider"] {
		l.provider.ErrorFn(500, "forged provider in redirect", res, req)
		return
	}

	// store state to session
	passedState := req.URL.Query().Get("state")
	l.addState(provName, passedState)
	http.Redirect(res, req, prov.AuthCodeURL(passedState), 302)
}

// doReturn handles oauthmw returns.
//
// Verifies passed oauth2 code, and state from the values stored in session,
// and then redeems (calls oauth2 Exchange) token.
//
// If successful, the oauth2 token will be stored in the session.
func (l login) doReturn(stateDec map[string]string, res http.ResponseWriter, req *http.Request) {
	// verify state belongs to this session
	if l.getSessionID() != stateDec["sid"] {
		l.provider.ErrorFn(500, "forged sid in return", res, req)
		return
	}

	// grab passed state
	passedState := req.URL.Query().Get("state")

	// grab state from session
	stateKey := fmt.Sprintf("%x", md5.Sum([]byte(passedState)))
	sess := l.sessionStore()
	storedState, ok := sess.States[stateKey]
	if !ok {
		l.provider.ErrorFn(500, "state not found in session", res, req)
		return
	}

	// verify that stored state has not expired yet
	if !storedState.Expiration.IsZero() && time.Now().After(storedState.Expiration) {
		l.provider.ErrorFn(500, "request expired. try again", res, req)
		return
	}

	// verify not already redeemed
	if storedState.Redeemed {
		l.provider.ErrorFn(500, "already redeemed. try again", res, req)
		return
	}

	// verify that stored provider is same as passed provider
	if stateDec["provider"] != storedState.Provider {
		l.provider.ErrorFn(500, "invalid provider", res, req)
		return
	}

	// grab redirect path
	resource, ok := stateDec["resource"]
	if !ok {
		l.provider.ErrorFn(500, "invalid resource", res, req)
		return
	}

	// use code for oauth2 exchange
	code := req.URL.Query().Get("code")
	token, err := l.provider.Configs[storedState.Provider].Exchange(oauth2Context, code)
	if err != nil {
		//log.Printf("error doing exchange with %s: %s", storedState.Provider, err)
		l.provider.ErrorFn(500, fmt.Sprintf("could not do exchange with %s", storedState.Provider), res, req)
		return
	}

	// verify token is valid
	if !token.Valid() {
		l.provider.ErrorFn(403, http.StatusText(403), res, req)
		return
	}

	// pass to checkFn
	if l.checkFn != nil {
		msg, ok := l.checkFn(storedState.Provider, l.provider.Configs[storedState.Provider], token)
		if !ok {
			l.provider.ErrorFn(500, msg, res, req)
			return
		}
	}

	// set token expiry if TokenLifetime specified and not already indicated
	tokenExpiry := time.Now().Add(l.provider.TokenLifetime)
	if l.provider.TokenLifetime > 0 && (sess.Token.Expiry.IsZero() || sess.Token.Expiry.After(tokenExpiry)) {
		sess.Token.Expiry = tokenExpiry
	}

	// save oauth2 token in session
	*(sess.Token) = *token
	sess.Provider = storedState.Provider

	// flag redeemed status
	storedState.Redeemed = true
	sess.States[stateKey] = storedState

	// redirect -- use 301 because token cannot be redeemed twice
	http.Redirect(res, req, resource, 301)
}

// redirectPath returns a built oauthmw redirect path for a provider.
func (l login) redirectPath(provName, state string) string {
	path := ""
	if l.provider.Path != "/" {
		path = l.provider.Path
	}
	return path + l.provider.RedirectPrefix + provName + "?state=" + url.QueryEscape(state)
}

// doProtectedPage handles protected page logic.
//
// If only one oauth2 provider, do redirect, otherwise output protected page
// template allowing user to select login mechanism.
func (l login) doProtectedPage(res http.ResponseWriter, req *http.Request) {
	// build sessionid for encodestate
	sid := l.getSessionID()

	// build path
	path := req.URL.Path
	if l.provider.SubRouter && l.provider.Path != "/" {
		path = l.provider.Path + req.URL.Path
	}

	// if only one in ConfigsOrder, then redirect
	if len(l.provider.ConfigsOrder) == 1 {
		provName := l.provider.ConfigsOrder[0]
		state, err := l.provider.EncodeState(sid, provName, path)
		if err != nil {
			l.provider.ErrorFn(500, fmt.Sprintf("could not encode state for %s", provName), res, req)
			return
		}

		http.Redirect(res, req, l.redirectPath(provName, state), 302)
		return
	}

	// build hrefs for template
	hrefs := make(map[string]string, len(l.provider.ConfigsOrder))
	for _, provName := range l.provider.ConfigsOrder {
		state, err := l.provider.EncodeState(sid, provName, path)
		if err != nil {
			l.provider.ErrorFn(500, fmt.Sprintf("could not encode state for %s (2)", provName), res, req)
			return
		}
		hrefs[provName] = l.redirectPath(provName, state)
	}

	l.provider.TemplateFn(hrefs, res, req)
}

// ServeHTTP handles oauth2 logic for the login middleware.
func (l login) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	// loop through states and do cleanup if enabled
	sess := l.sessionStore()
	if l.provider.CleanupStates && len(sess.States) >= l.provider.MaxStates {
		expiration := time.Now()
		for h, s := range sess.States {
			if expiration.After(s.Expiration) {
				delete(sess.States, h)
			}
		}
	}

	// grab last page, and check if matches special paths
	if i := strings.LastIndexByte(req.URL.Path, '/'); i >= 0 {
		path := req.URL.Path[i:]
		if strings.HasPrefix(path, l.provider.PagePrefix) {
			// decode passed state
			passedState := req.URL.Query().Get("state")
			stateDec, err := l.provider.DecodeState(passedState)

			switch {
			// state properly decoded and is a redirect path
			case err == nil && strings.HasPrefix(path, l.provider.RedirectPrefix):
				l.doRedirect(path[len(l.provider.RedirectPrefix):], stateDec, res, req)
				return

			// state properly decoded and is return (login) path
			case err == nil && path == l.provider.ReturnName:
				l.doReturn(stateDec, res, req)

				return
			}
		}
	}

	// run protected page logic if login required and
	// token invalid, expired, or otherwise bad
	token, expired, ok := l.getToken()
	if l.required && (!ok || expired || token == nil || !token.Valid()) {
		l.doProtectedPage(res, req)
		return
	}

	// pass to next middleware
	l.h.ServeHTTP(res, req)
}
