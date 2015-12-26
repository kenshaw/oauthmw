package oauthmw

import (
	"crypto/md5"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/context"

	"goji.io"
	"goji.io/pat"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/google"

	"github.com/knq/oauthlib"
	"github.com/knq/sessionmw"

	"github.com/gorilla/securecookie"
)

const oauthmwcookie = "oauthmw_test"

var rexp = regexp.MustCompile(`(?i)` + oauthmwcookie + `=[^;\s]*`)

func okHandler(ctx context.Context, res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(200)
	fmt.Fprintf(res, "OK")
}

func get(mux *goji.Mux, path string, cookie *http.Cookie, t *testing.T) (*httptest.ResponseRecorder, string) {
	rr := httptest.NewRecorder()
	q, _ := http.NewRequest("GET", path, nil)
	if cookie != nil {
		q.AddCookie(cookie)
	}
	mux.ServeHTTP(rr, q)

	l := ""

	switch {
	case rr.Code >= 300 && rr.Code < 400:
		if len(rr.HeaderMap["Location"]) != 1 {
			t.Errorf("code %d redirect had 0 or more than 1 location header (count: %d)", rr.Code, len(rr.HeaderMap["Location"]))
		} else {
			l = rr.HeaderMap["Location"][0]
			if len(l) < 1 {
				t.Error("redirect location should not be empty string")
			}
		}
	}

	return rr, l
}

func getCookie(rr *httptest.ResponseRecorder, t *testing.T) *http.Cookie {
	cookieStr := rexp.FindString(rr.HeaderMap["Set-Cookie"][0])
	cookie := &http.Cookie{
		Name:  oauthmwcookie,
		Value: cookieStr[strings.Index(cookieStr, "=")+1:],
	}

	// sanity check
	if len(cookie.Value) < 1 {
		t.Errorf("cookie should not be empty")
	}

	return cookie
}

func check(code int, rr *httptest.ResponseRecorder, t *testing.T) {
	if code != rr.Code {
		t.Logf("GOT: %d -- %s", rr.Code, rr.Body.String())
		t.Errorf("expected %d, got: %d", code, rr.Code)
	}
}

func checkOK(rr *httptest.ResponseRecorder, t *testing.T) {
	if rr.Code != 200 || rr.Body.String() != "OK" {
		t.Error("should be passed to okHandler")
	}
}

func checkError(code int, err string, rr *httptest.ResponseRecorder, t *testing.T) {
	body := strings.TrimSpace(rr.Body.String())
	if code != rr.Code || err != body {
		t.Logf("GOT: %d -- %s", rr.Code, body)
		t.Errorf("should be '%s' error", err)
	}
}

func urlParse(str string, t *testing.T) *url.URL {
	u, err := url.Parse(str)
	if err != nil {
		t.Errorf("location did not parse correctly: %s -- %s", err, str)
	}

	return u
}

var ErrRedirectAttempted = errors.New("redirect attempted")

func newClient(serverurl string) *http.Client {
	// create a http client with requests proxied to httptest server
	return &http.Client{
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return url.Parse(serverurl)
			},
		},

		// prevent redirects from happening
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return ErrRedirectAttempted
		},
	}
}

func checkAuthResp(resp *http.Response, err error, t *testing.T) *url.URL {
	if ue, ok := err.(*url.Error); ok && ue.Err == ErrRedirectAttempted {
		err = nil
	}

	if err != nil {
		t.Errorf("should not encounter error: %s", err)
	}

	// check that authorization is redirect back to local
	if resp.StatusCode != 302 {
		t.Errorf("should be redirect")
	}

	// do some sanity checks
	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Errorf("returned body should be url, got: %s", u)
	}

	return u
}

func encodeState(prov *Provider, sid, provName, resource string, t *testing.T) string {
	state, err := prov.EncodeState(sid, provName, resource)
	if err != nil {
		t.Fatalf("no error should be produced for EncodeState, got: %s", err)
	}

	return url.QueryEscape(state)
}

func encodeBadState(p *Provider, state map[string]string, t *testing.T) string {
	sc := securecookie.New([]byte(p.Secret), []byte(p.BlockSecret))
	sc.MaxAge(int(p.StateLifetime))

	s, err := sc.Encode(p.SessionKey, state)
	if err != nil {
		t.Error("encodeBadState should not error")
	}

	return s
}

func newSession() *sessionmw.Config {
	return &sessionmw.Config{
		Name:        oauthmwcookie,
		Secret:      []byte("7mXpHr7GUKIVJT9TmY95i1UnvRKa0iKj"),
		BlockSecret: []byte("LxUpc1GPFKFQ5tMpciQAgv5o80yuzBzH"),
		Store:       sessionmw.NewMemStore(),
	}
}

func newProvider() Provider {
	return Provider{
		Secret:        []byte("hKpY8Dxs8vVz1AQdPw5FsbNAuLC37HQ1"),
		BlockSecret:   []byte("ssvNF6rj1etwgQdsMFqUw45VFVENYg0q"),
		Path:          "/",
		CleanupStates: true,
		Configs:       map[string]*oauth2.Config{},
	}
}

func newOauthlibServer(t *testing.T) *http.ServeMux {
	server := oauthlib.NewServer(oauthlib.NewServerConfig(), oauthlib.NewTestStorage(t))

	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		resp.ResponseType = oauthlib.REDIRECT

		if ar := server.HandleAuthorizeRequest(resp, r); ar != nil {
			ar.Authorized = true
			server.FinishAuthorizeRequest(resp, r, ar)
		}
		oauthlib.WriteJSON(w, resp)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		if ar := server.HandleAccessRequest(resp, r); ar != nil {
			ar.Authorized = true

			server.FinishAccessRequest(resp, r, ar)
		}

		code := r.PostFormValue("code")
		if code == "badcode" {
			http.Error(w, "badcode", 500)
			return
		}

		oauthlib.WriteJSON(w, resp)
	})

	return mux
}

func newOauthlibEndpoint(serverurl string) *oauth2.Config {
	// must use hard coded values from example.TestStorage
	return &oauth2.Config{
		Endpoint: oauth2.Endpoint{
			AuthURL:  serverurl + "/authorize",
			TokenURL: serverurl + "/token",
		},
		ClientID:     "1234",
		ClientSecret: "aabbccdd",
		RedirectURL:  "http://localhost:14000/appauth",
		Scopes: []string{
			"everything",
		},
	}
}

func newGoogleEndpoint(redir string) *oauth2.Config {
	return &oauth2.Config{
		Endpoint:     google.Endpoint,
		ClientID:     "",
		ClientSecret: "",
		RedirectURL:  redir,
		Scopes: []string{
			"https://www.googleapis.com/auth/plus.login",
			"https://www.googleapis.com/auth/userinfo.email",
		},
	}
}

func newFacebookEndpoint(redir string) *oauth2.Config {
	return &oauth2.Config{
		Endpoint:     facebook.Endpoint,
		ClientID:     "",
		ClientSecret: "",
		RedirectURL:  redir,
		Scopes: []string{
			"public_profile,email",
		},
	}
}

func newCheckFunc(ret bool, t *testing.T) CheckFn {
	return func(provName string, config *oauth2.Config, token *oauth2.Token) (string, bool) {
		msg := ""
		if !ret {
			msg = "invalid login"
		}

		if provName != "oauthlib" {
			t.Errorf("provider should be oauthlib")
		}

		if config == nil {
			t.Errorf("config should not be nil")
		}

		if token == nil {
			t.Errorf("token should not be nil")
		}

		return msg, ret
	}
}

func TestProviderEmptySecret(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("should panic")
		}
	}()

	_ = Provider{}.Login(nil)
}

func TestProviderEmptyBlockSecret(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("should panic")
		}
	}()

	_ = Provider{Secret: []byte("123")}.Login(nil)
}

func TestProviderEmptyPath(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("should panic")
		}
	}()

	_ = Provider{Secret: []byte("123"), BlockSecret: []byte("123")}.Login(nil)
}

func getSid(sess sessionmw.Store, prov *Provider, t *testing.T) string {
	mstore, ok := sess.(*sessionmw.MemStore)
	if !ok {
		t.Fatal("session store should be convertible")
	}

	if len(mstore.Data) != 1 {
		t.Fatal("store should have exactly one key")
	}

	// loop over store
	for k := range mstore.Data {
		return fmt.Sprintf("%x", md5.Sum([]byte(k)))
	}

	return ""
}

func TestLogin(t *testing.T) {
	// setup oauthmw
	sess := newSession()
	prov := newProvider()
	prov.Path = "/"
	prov.Configs = map[string]*oauth2.Config{
		"google":   newGoogleEndpoint(""),
		"facebook": newFacebookEndpoint(""),
	}
	prov.checkDefaults()

	// setup mux and middleware
	m0 := goji.NewMux()
	m0.UseC(sess.Handler)
	m0.UseC(prov.Login(nil))
	m0.HandleFuncC(pat.Get("/ok"), okHandler)

	// do initial request to establish session
	r0, _ := get(m0, "/ok", nil, t)
	checkOK(r0, t)
	cookie := getCookie(r0, t)

	// verify 404 if no/bad state provided
	r1, _ := get(m0, "/oauth-redirect-google", cookie, t)
	check(404, r1, t)

	// verify redirect when correct state provided
	s2 := encodeState(&prov, getSid(sess.Store, &prov, t), "google", "/resource", t)
	r2, l2 := get(m0, "/oauth-redirect-google?state="+s2, cookie, t)
	check(302, r2, t)

	if !strings.HasPrefix(l2, "https://accounts.google.com/o/oauth2/auth?client_id=") {
		t.Errorf("redirect should be to google, got: %s", l2)
	}
}

func TestRequireLoginAutoRedirect(t *testing.T) {
	// setup mux's
	m0 := goji.NewMux()

	m1 := goji.NewMux()
	m1Sub := goji.NewMux()
	m1.HandleC(pat.Get("/p/*"), m1Sub)

	m2 := goji.NewMux()
	m2Sub := goji.NewMux()
	m2.HandleC(pat.Get("/p/*"), m2Sub)

	tests := []struct {
		mux      *goji.Mux
		addToMux *goji.Mux
		path     string
		redir    string
	}{
		{m0, m0, "/", "/oauth-redirect-google?state="},
		{m1, m1, "/", "/oauth-redirect-google?state="},
		/*{m1, m1Sub, "/p/", "/p/oauth-redirect-google?state="},
		{m2, m2, "/p/", "/p/oauth-redirect-google?state="},
		{m2, m2Sub, "/p/", "/p/oauth-redirect-google?state="},*/
	}

	for i, test := range tests {
		// setup middleware
		sess := newSession()
		prov := newProvider()
		prov.Path = test.path
		prov.Configs = map[string]*oauth2.Config{
			"google": newGoogleEndpoint(""),
		}

		// enable subrouter test for m2Sub
		/*if test.addToMux == m2Sub {
			prov.SubRouter = true
		}*/

		// add middleware to mux
		sessmw := sess.Handler
		rlmw := prov.RequireLogin(nil)
		test.addToMux.UseC(sessmw)
		test.addToMux.UseC(rlmw)

		// check for redirect
		r0, l0 := get(test.mux, test.path, nil, t)
		check(302, r0, t)
		if !strings.HasPrefix(l0, test.redir) {
			t.Errorf("test %d invalid redirect %s", i, l0)
		}

		// remove middleware from mux so they can be reused
		//test.addToMux.Abandon(rlmw)
		//test.addToMux.Abandon(sessmw)
	}
}

func TestRequireLoginFlow(t *testing.T) {
	// setup test oauth server
	server := httptest.NewServer(newOauthlibServer(t))
	defer server.Close()

	// set oauth2context HTTPClient to force oauth2 Exchange to use it
	client := newClient(server.URL)
	oauth2Context = context.WithValue(oauth2Context, oauth2.HTTPClient, client)

	// oauth2 configs for use
	configs := map[string]*oauth2.Config{
		"google":   newGoogleEndpoint(""),
		"facebook": newFacebookEndpoint(""),
		"oauthlib": newOauthlibEndpoint(server.URL),
	}

	tests := []struct {
		path string
		req  string
		exp  []string
	}{
		{"/", "/resource", []string{
			"/oauth-redirect-google?state=",
			"/oauth-redirect-facebook?state=",
			"/oauth-redirect-oauthlib?state=",
		}},

		{"/p", "/p/resource", []string{
			"/p/oauth-redirect-google?state=",
			"/p/oauth-redirect-facebook?state=",
			"/p/oauth-redirect-oauthlib?state=",
		}},
	}

	for i, test := range tests {
		// build oauthmw
		prov := newProvider()
		sess := newSession()
		prov.Path = test.path
		prov.Configs = configs
		prov.TokenLifetime = 1 * time.Minute

		// setup mux and middleware
		m0 := goji.NewMux()
		m0.UseC(sess.Handler)
		m0.UseC(prov.RequireLogin(nil))
		m0.HandleFuncC(pat.Get("/*"), okHandler)

		// do initial request to establish session
		r0, _ := get(m0, test.req, nil, t)
		check(200, r0, t)
		cookie := getCookie(r0, t)

		// verify we DIDN'T hit the OK handler
		b0 := strings.TrimSpace(r0.Body.String())
		if b0 == "OK" {
			t.Errorf("body should not be OK")
		}

		// verify that redirects are present for each oauth2 config
		for _, str := range test.exp {
			if !strings.Contains(b0, `href="`+str) {
				t.Errorf("test %d should contain %s", i, str)
			}
		}

		// grab hrefs from page
		matches := regexp.MustCompile(`(?i)href="([^"]+)"`).FindAllStringSubmatch(b0, -1)

		// loop over matches and test href for each
		for _, match := range matches {
			// check that the request correctly generates redirect, and is valid url
			r1, l1 := get(m0, match[1], cookie, t)
			check(302, r1, t)
			u0, err := url.Parse(l1)
			if err != nil {
				t.Errorf("location did not parse correctly: %s -- %s", err, u0)
			}

			// if this is the local (oauthlib) endpoint, then do actual
			// authorization from oauthlib server
			if strings.HasPrefix(l1, server.URL) {
				// do authorization
				resp, err := client.Get(l1)
				u1 := checkAuthResp(resp, err, t)

				// change path due to hard coded values in
				// oauthlib/example.TestStorage
				u1.Path = test.path + "/oauth-login"

				// do oauth-login
				r2, l2 := get(m0, u1.String(), cookie, t)
				check(301, r2, t)

				// verify redirect resource path is same as original request
				if test.req != l2 {
					t.Errorf("test %d req path (%s) redir should be same after auth, got: %s", i, test.req, l2)
				}

				// check original resource path now passes to 'OK' handler
				r3, _ := get(m0, test.req, cookie, t)
				checkOK(r3, t)

				// check for double redemption error
				r4, _ := get(m0, u1.String(), cookie, t)
				checkError(500, "already redeemed. try again", r4, t)
			}
		}
	}

	// reset context
	oauth2Context = oauth2.NoContext
}

func TestCheckFnGood(t *testing.T) {
	// setup test oauth server
	server := httptest.NewServer(newOauthlibServer(t))
	defer server.Close()

	// set oauth2context HTTPClient to force oauth2 Exchange to use it
	client := newClient(server.URL)
	oauth2Context = context.WithValue(oauth2Context, oauth2.HTTPClient, client)

	// build oauthmw
	prov := newProvider()
	sess := newSession()
	prov.Path = "/"
	prov.Configs = map[string]*oauth2.Config{
		"oauthlib": newOauthlibEndpoint(server.URL),
	}

	// setup mux and middleware
	m0 := goji.NewMux()
	m0.UseC(sess.Handler)
	m0.UseC(prov.RequireLogin(newCheckFunc(true, t)))
	m0.HandleFuncC(pat.Get("/*"), okHandler)

	// do initial request to establish session
	r0, l0 := get(m0, "/", nil, t)
	check(302, r0, t)
	cookie := getCookie(r0, t)

	// do redirect
	r1, l1 := get(m0, l0, cookie, t)
	check(302, r1, t)
	urlParse(l1, t)
	if !strings.HasPrefix(l1, server.URL) {
		t.Fatalf("should be server.URL, got: %s", l0)
	}

	// do authorization
	resp, err := client.Get(l1)
	u1 := checkAuthResp(resp, err, t)

	// change path due to hard coded values in
	// oauthlib/example.TestStorage
	u1.Path = "/oauth-login"

	// do oauth-login
	r2, l2 := get(m0, u1.String(), cookie, t)
	check(301, r2, t)

	// verify redirect resource path is same as original request
	if "/" != l2 {
		t.Errorf("redirect path should be /, got: %s", l2)
	}

	// check original resource path now passes to 'OK' handler
	r3, _ := get(m0, "/", cookie, t)
	checkOK(r3, t)

	// reset context
	oauth2Context = oauth2.NoContext
}

func TestCheckFnBad(t *testing.T) {
	// setup test oauth server
	server := httptest.NewServer(newOauthlibServer(t))
	defer server.Close()

	// set oauth2context HTTPClient to force oauth2 Exchange to use it
	client := newClient(server.URL)
	oauth2Context = context.WithValue(oauth2Context, oauth2.HTTPClient, client)

	// build oauthmw
	prov := newProvider()
	sess := newSession()
	prov.Path = "/"
	prov.Configs = map[string]*oauth2.Config{
		"oauthlib": newOauthlibEndpoint(server.URL),
	}

	// setup mux and middleware
	m0 := goji.NewMux()
	m0.UseC(sess.Handler)
	m0.UseC(prov.RequireLogin(newCheckFunc(false, t)))
	m0.HandleFuncC(pat.Get("/*"), okHandler)

	// do initial request to establish session
	r0, l0 := get(m0, "/", nil, t)
	check(302, r0, t)
	cookie := getCookie(r0, t)

	// do redirect
	r1, l1 := get(m0, l0, cookie, t)
	check(302, r1, t)
	urlParse(l1, t)
	if !strings.HasPrefix(l1, server.URL) {
		t.Fatalf("should be server.URL, got: %s", l0)
	}

	// do authorization
	resp, err := client.Get(l1)
	u1 := checkAuthResp(resp, err, t)

	// change path due to hard coded values in
	// oauthlib/example.TestStorage
	u1.Path = "/oauth-login"

	// do oauth-login
	r2, _ := get(m0, u1.String(), cookie, t)
	checkError(500, "invalid login", r2, t)

	// reset context
	oauth2Context = oauth2.NoContext
}

// test really long resource paths (limit to what securecookie can encode)
func TestInvalidStates(t *testing.T) {
	// resource path
	respath := "/" + strings.Repeat("x", 4096)

	// setup oauthmw
	sess := newSession()
	prov := newProvider()
	prov.Path = "/"
	prov.Configs = map[string]*oauth2.Config{
		"google": newGoogleEndpoint(""),
	}

	// setup mux and middleware
	m0 := goji.NewMux()
	m0.UseC(sess.Handler)
	m0.UseC(prov.RequireLogin(nil))
	m0.HandleFuncC(pat.Get("/*"), okHandler)

	r0, _ := get(m0, respath, nil, t)
	checkError(500, "could not encode state for google", r0, t)

	//--------------------------------------
	// repeat above test, but with multiple providers
	prov.Configs["facebook"] = newFacebookEndpoint("")

	// setup mux and middleware
	m1 := goji.NewMux()
	m1.UseC(sess.Handler)
	m1.UseC(prov.RequireLogin(nil))
	m1.HandleFuncC(pat.Get("/*"), okHandler)

	r1, _ := get(m1, respath, nil, t)
	checkError(500, "could not encode state for facebook (2)", r1, t)
}

func checkStatesCount(sess sessionmw.Store, prov *Provider, count int, msg string, t *testing.T) {
	mstore, ok := sess.(*sessionmw.MemStore)
	if !ok {
		t.Fatal("session store should be convertible")
	}

	if len(mstore.Data) != 1 {
		t.Fatal("store should have exactly one key")
	}

	// loop over store
	for _, item := range mstore.Data {
		sessStore, ok := item.(map[string]interface{})[prov.SessionKey].(Store)
		if !ok {
			t.Fatal("item should be of type Store")
		}

		if len(sessStore.States) != count {
			t.Error(msg)
		}
	}
}

func TestStatesCleanup(t *testing.T) {
	// setup oauthmw
	sess := newSession()
	prov := newProvider()
	prov.Path = "/"
	prov.StateLifetime = 1 * time.Second
	prov.Configs = map[string]*oauth2.Config{
		"google": newGoogleEndpoint(""),
	}
	prov.checkDefaults()

	// setup mux and middleware
	m0 := goji.NewMux()
	m0.UseC(sess.Handler)
	m0.UseC(prov.Login(nil))
	m0.HandleFuncC(pat.Get("/ok"), okHandler)

	// do initial request to establish session
	r0, _ := get(m0, "/ok", nil, t)
	checkOK(r0, t)
	cookie := getCookie(r0, t)

	// add a lot of states
	for i := 0; i < 2*DefaultMaxStates; i++ {
		// do redirect request to have state added to session
		s1 := encodeState(&prov, getSid(sess.Store, &prov, t), "google", "/resource", t)
		r1, l1 := get(m0, "/oauth-redirect-google?state="+s1, cookie, t)
		check(302, r1, t)

		// verify redirect is correct
		if !strings.HasPrefix(l1, "https://accounts.google.com/o/oauth2/auth?client_id=") {
			t.Errorf("redirect should be to google, got: %s", l1)
		}
	}

	checkStatesCount(sess.Store, &prov, 2*DefaultMaxStates, "states count should be 2*DefaultMaxStates", t)

	// expire all states
	setStatesExpiration(sess.Store, &prov, time.Now().Add(-1*time.Hour), t)

	// kick cleanup
	r2, _ := get(m0, "/ok", cookie, t)
	checkOK(r2, t)

	checkStatesCount(sess.Store, &prov, 0, "states should be empty after cleanup", t)
}

func TestRedirectErrors(t *testing.T) {
	// setup oauthmw
	sess := newSession()
	prov := newProvider()
	prov.Path = "/"
	prov.Configs = map[string]*oauth2.Config{
		"google":   newGoogleEndpoint(""),
		"facebook": newFacebookEndpoint(""),
	}
	prov.checkDefaults()

	// setup mux and middleware
	m0 := goji.NewMux()
	m0.UseC(sess.Handler)
	m0.UseC(prov.Login(nil))
	m0.HandleFuncC(pat.Get("/ok"), okHandler)

	// do initial request to establish session
	r0, _ := get(m0, "/ok", nil, t)
	checkOK(r0, t)
	cookie := getCookie(r0, t)

	// encode correct state
	s0 := encodeState(&prov, getSid(sess.Store, &prov, t), "google", "/resource", t)

	// check bad provider
	r1, _ := get(m0, "/oauth-redirect-bad?state="+s0, cookie, t)
	checkError(500, "invalid provider", r1, t)

	// check forged sid
	s2 := encodeState(&prov, "", "google", "/resource", t)
	r2, _ := get(m0, "/oauth-redirect-google?state="+s2, cookie, t)
	checkError(500, "forged sid in redirect", r2, t)

	// check forged provider
	r3, _ := get(m0, "/oauth-redirect-facebook?state="+s0, cookie, t)
	checkError(500, "forged provider in redirect", r3, t)
}

func setStatesExpiration(sess sessionmw.Store, prov *Provider, expiration time.Time, t *testing.T) {
	mstore, ok := sess.(*sessionmw.MemStore)
	if !ok {
		t.Fatal("session store should be convertible")
	}

	if len(mstore.Data) != 1 {
		t.Fatal("store should have exactly one key")
	}

	// loop over store
	for _, item := range mstore.Data {
		sessStore, ok := item.(map[string]interface{})[prov.SessionKey].(Store)
		if !ok {
			t.Fatal("item should be of type Store")
		}

		if len(sessStore.States) < 1 {
			t.Fatal("there should be at least one saved state")
		}

		// loop over states
		for k, state := range sessStore.States {
			// overwrite state status
			sessStore.States[k] = StoreState{
				Provider:   state.Provider,
				Expiration: expiration,
				Redeemed:   state.Redeemed,
			}
		}
	}
}

func addBadState(sess sessionmw.Store, prov *Provider, state map[string]string, t *testing.T) string {
	badState := encodeBadState(prov, state, t)

	key := fmt.Sprintf("%x", md5.Sum([]byte(badState)))

	mstore, ok := sess.(*sessionmw.MemStore)
	if !ok {
		t.Fatal("session store should be convertible")
	}

	if len(mstore.Data) != 1 {
		t.Fatal("store should have exactly one key")
	}

	// loop over store
	for _, item := range mstore.Data {
		sessStore, ok := item.(map[string]interface{})[prov.SessionKey].(Store)
		if !ok {
			t.Fatal("item should be of type Store")
		}
		sessStore.States[key] = StoreState{
			Provider: "oauthlib",
		}
	}

	return badState
}

func TestReturnErrors(t *testing.T) {
	// setup test oauth server
	server := httptest.NewServer(newOauthlibServer(t))
	defer server.Close()

	// set oauth2context HTTPClient to force oauth2 Exchange to use it
	client := newClient(server.URL)
	oauth2Context = context.WithValue(oauth2Context, oauth2.HTTPClient, client)

	// setup oauthmw
	prov := newProvider()
	sess := newSession()
	prov.Path = "/"
	prov.Configs = map[string]*oauth2.Config{
		"oauthlib": newOauthlibEndpoint(server.URL),
	}
	prov.checkDefaults()

	// setup mux and middleware
	m0 := goji.NewMux()
	m0.UseC(sess.Handler)
	m0.UseC(prov.RequireLogin(nil))
	m0.HandleFuncC(pat.Get("/*"), okHandler)

	// do initial request to establish session
	r00, _ := get(m0, "/", nil, t)
	check(302, r00, t)
	cookie := getCookie(r00, t)

	// do redirect request to have state added to session
	s0 := encodeState(&prov, getSid(sess.Store, &prov, t), "oauthlib", "/resource", t)
	r0, l0 := get(m0, "/oauth-redirect-oauthlib?state="+s0, cookie, t)
	check(302, r0, t)
	urlParse(l0, t)

	// verify redirect is to oauthlib server
	if !strings.HasPrefix(l0, server.URL) {
		t.Fatalf("redir location should be server.URL, got: %s", l0)
	}

	// do authorize request with oauthlib server
	resp, err := client.Get(l0)
	u1 := checkAuthResp(resp, err, t)

	// change return path due to hard coded values in oauthlib/example.TestStorage
	u1.Path = "/oauth-login"

	// check exchange error
	q1 := fmt.Sprintf("code=%s&state=%s", "badcode", s0)
	r1, _ := get(m0, "/oauth-login?"+q1, cookie, t)
	checkError(500, "could not do exchange with oauthlib", r1, t)

	// check state not present in session
	q2 := fmt.Sprintf(
		"code=%s&state=%s",
		url.QueryEscape(u1.Query().Get("code")),
		encodeState(&prov, getSid(sess.Store, &prov, t), "oauthlib", "/resource", t),
	)
	r2, _ := get(m0, "/oauth-login?"+q2, cookie, t)
	checkError(500, "state not found in session", r2, t)

	// expire states
	setStatesExpiration(sess.Store, &prov, time.Now().Add(-1*time.Hour), t)

	// check that expired states are not redeemable
	r3, _ := get(m0, u1.String(), cookie, t)
	checkError(500, "request expired. try again", r3, t)

	// reset states expiration
	setStatesExpiration(sess.Store, &prov, time.Now().Add(1*time.Hour), t)

	// check bad sid in state
	q4 := fmt.Sprintf("code=%s&state=%s",
		u1.Query().Get("code"),
		addBadState(sess.Store, &prov, map[string]string{
			"sid":      "",
			"provider": "oauthlib",
			"resource": "/resource",
		}, t),
	)
	r4, _ := get(m0, "/oauth-login?"+q4, cookie, t)
	checkError(500, "forged sid in return", r4, t)

	// check bad provider in state
	q5 := fmt.Sprintf("code=%s&state=%s",
		u1.Query().Get("code"),
		addBadState(sess.Store, &prov, map[string]string{
			"sid":      getSid(sess.Store, &prov, t),
			"provider": "",
			"resource": "/resource",
		}, t),
	)
	r5, _ := get(m0, "/oauth-login?"+q5, cookie, t)
	checkError(500, "invalid provider", r5, t)

	// check bad resource in state
	q6 := fmt.Sprintf("code=%s&state=%s",
		u1.Query().Get("code"),
		addBadState(sess.Store, &prov, map[string]string{
			"sid":      getSid(sess.Store, &prov, t),
			"provider": "oauthlib",
		}, t),
	)
	r6, _ := get(m0, "/oauth-login?"+q6, cookie, t)
	checkError(500, "invalid resource", r6, t)

	// check bad auth token passed from oauth server
	q7 := fmt.Sprintf("code=%s&state=%s", "badtoken", s0)
	r7, _ := get(m0, "/oauth-login?"+q7, cookie, t)
	checkError(403, http.StatusText(403), r7, t)

	// reset context
	oauth2Context = oauth2.NoContext
}

// gets the item in the session, and returns it
// corrupts the actual item with passed item
func swapSessionStore(sess sessionmw.Store, prov *Provider, obj interface{}, doErr bool, t *testing.T) interface{} {
	mstore, ok := sess.(*sessionmw.MemStore)
	if !ok {
		t.Fatal("session store should be convertible")
	}

	if len(mstore.Data) != 1 {
		t.Fatal("store should have exactly one key")
	}

	// loop over store
	var sessStore interface{}
	for _, item := range mstore.Data {
		sessStore, ok = item.(map[string]interface{})[prov.SessionKey].(Store)
		if !ok && doErr {
			t.Fatal("item should be of type Store")
		}

		item.(map[string]interface{})[prov.SessionKey] = obj
	}

	return sessStore
}

func TestSessionStore(t *testing.T) {
	// setup oauthmw
	sess := newSession()
	prov := newProvider()
	prov.Path = "/"
	prov.Configs = map[string]*oauth2.Config{
		"google": newGoogleEndpoint(""),
	}
	prov.checkDefaults()

	// setup mux and middleware
	m0 := goji.NewMux()
	m0.UseC(sess.Handler)
	m0.UseC(prov.Login(nil))
	m0.HandleFuncC(pat.Get("/ok"), okHandler)

	// do initial request to establish session
	r0, _ := get(m0, "/ok", nil, t)
	checkOK(r0, t)
	cookie := getCookie(r0, t)

	// set session store to bad data
	obj0 := swapSessionStore(sess.Store, &prov, "baddata", true, t)
	_, ok := obj0.(Store)
	if !ok {
		t.Error("item in session should be store")
	}

	// send another request
	r1, _ := get(m0, "/ok", cookie, t)
	checkOK(r1, t)

	// check that store is no longer corrupted
	obj1 := swapSessionStore(sess.Store, &prov, obj0, true, t)
	_, ok = obj1.(Store)
	if !ok {
		t.Error("store should have been fixed")
	}

	// test nil token
	_ = swapSessionStore(sess.Store, &prov, Store{Token: nil}, false, t)
	r2, _ := get(m0, "/ok", cookie, t)
	checkOK(r2, t)

	// setup mux and middleware
	m1 := goji.NewMux()
	m1.UseC(sess.Handler)
	m1.UseC(prov.RequireLogin(nil))
	m1.HandleFuncC(pat.Get("/ok"), okHandler)

	// check expired token
	r3, _ := get(m1, "/ok", cookie, t)
	check(302, r3, t)

	// create token
	t3 := oauth2.Token{
		AccessToken: "access",
		TokenType:   "bearer",
		Expiry:      time.Now().Add(1 * time.Hour),
	}

	// put token in session
	swapSessionStore(sess.Store, &prov, Store{
		Token:  &t3,
		States: make(map[string]StoreState),
	}, true, t)

	// check access
	r4, _ := get(m1, "/ok", cookie, t)
	checkOK(r4, t)

	// force token expiration
	t3.Expiry = time.Now().Add(-1 * time.Hour)

	// check that access has been revoked
	r5, _ := get(m1, "/ok", cookie, t)
	check(302, r5, t)
}

// test multiple / different sub paths. each should still require login
// even if another has already been authenticated
/*func TestMultipleMiddlewarePaths(t *testing.T) {

}*/
