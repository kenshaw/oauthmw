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

	"github.com/RangelReale/osin"
	"github.com/RangelReale/osin/example"
	"github.com/gorilla/securecookie"
	"github.com/ymichael/sessions"
	"github.com/zenazn/goji/web"
	gojimw "github.com/zenazn/goji/web/middleware"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/google"
)

const oauthmwcookie = "oauthmw_test"

var rexp = regexp.MustCompile(`(?i)` + oauthmwcookie + `=[^;\s]*`)

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

func okHandler(wctx web.C, res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(200)
	fmt.Fprintf(res, "OK")
}

func checkOK(msg string, rr *httptest.ResponseRecorder, t *testing.T) {
	if rr.Code != 200 || rr.Body.String() != "OK" {
		t.Error(msg)
	}
}

func checkError(code int, err string, rr *httptest.ResponseRecorder, t *testing.T) {
	body := strings.TrimSpace(rr.Body.String())
	if code != rr.Code || err != body {
		t.Logf("GOT: %d -- %s", rr.Code, body)
		t.Error(fmt.Sprintf("should be '%s' error", err))
	}
}

var RedirectAttemptedError = errors.New("redirect")

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
			return RedirectAttemptedError
		},
	}
}

func checkAuthResp(resp *http.Response, err error, t *testing.T) *url.URL {
	if urlError, ok := err.(*url.Error); ok && urlError.Err == RedirectAttemptedError {
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
	sc.MaxAge(int(p.SessionLifetime))

	s, err := sc.Encode(p.SessionKey, state)
	if err != nil {
		t.Error("encodeBadState should not error")
	}

	return s
}

func newSession() *sessions.SessionOptions {
	return &sessions.SessionOptions{
		Name:          oauthmwcookie,
		Secret:        "7mXpHr7GUKIVJT9TmY95i1UnvRKa0iKj",
		ObjEnvKey:     "sessionObject",
		SidEnvKey:     "sessionId",
		Store:         &sessions.MemoryStore{},
		CookieOptions: &sessions.CookieOptions{"/", 0, true, false},
	}
}

func newProvider() Provider {
	return Provider{
		Secret:        "hKpY8Dxs8vVz1AQdPw5FsbNAuLC37HQ1",
		BlockSecret:   "ssvNF6rj1etwgQdsMFqUw45VFVENYg0q",
		Path:          "/",
		CleanupStates: true,
		Configs:       map[string]*oauth2.Config{},
	}
}

func newOsinServer() *http.ServeMux {
	server := osin.NewServer(osin.NewServerConfig(), example.NewTestStorage())

	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		resp.Type = osin.REDIRECT
		defer resp.Close()

		if ar := server.HandleAuthorizeRequest(resp, r); ar != nil {
			ar.Authorized = true
			server.FinishAuthorizeRequest(resp, r, ar)
		}
		osin.OutputJSON(resp, w, r)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		defer resp.Close()

		if ar := server.HandleAccessRequest(resp, r); ar != nil {
			ar.Authorized = true

			server.FinishAccessRequest(resp, r, ar)
		}

		code := r.PostFormValue("code")
		if code == "badcode" {
			http.Error(w, "badcode", 500)
			return
		}

		osin.OutputJSON(resp, w, r)
	})

	return mux
}

func newOsinEndpoint(serverurl string) *oauth2.Config {
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

	_ = Provider{Secret: "123"}.Login(nil)
}

func TestProviderEmptyPath(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("should panic")
		}
	}()

	_ = Provider{Secret: "123", BlockSecret: "123"}.Login(nil)
}

func getSid(prov *Provider, t *testing.T) string {
	mstore, ok := prov.Session.Store.(*sessions.MemoryStore)
	if !ok {
		t.Fatal("session store should be convertible")
	}

	// convert again
	store := map[string]map[string]interface{}(*mstore)
	if len(store) != 1 {
		t.Fatal("store should have exactly one key")
	}

	// loop over store
	for k, _ := range store {
		return fmt.Sprintf("%x", md5.Sum([]byte(k)))
	}

	return ""
}

func TestLogin(t *testing.T) {
	sess := newSession()
	prov := newProvider()
	prov.Session = sess
	prov.Path = "/"
	prov.Configs = map[string]*oauth2.Config{
		"google":   newGoogleEndpoint(""),
		"facebook": newFacebookEndpoint(""),
	}
	prov.checkDefaults()

	m0 := web.New()
	m0.Use(sess.Middleware())
	m0.Use(prov.Login(func() bool {
		return true
	}))
	m0.Handle("/ok", okHandler)

	r0 := httptest.NewRecorder()
	q0, _ := http.NewRequest("GET", "/ok", nil)
	m0.ServeHTTP(r0, q0)
	checkOK("should fall to okHandler", r0, t)

	// grab cookie from request
	cookie := getCookie(r0, t)

	// test oauth paths
	r1 := httptest.NewRecorder()
	q1, _ := http.NewRequest("GET", "/oauth-redirect-google", nil)
	q1.AddCookie(cookie)
	m0.ServeHTTP(r1, q1)

	// should be 404 if bad/no state passed
	if r1.Code != 404 {
		t.Error("should be 404")
	}

	s2 := encodeState(&prov, getSid(&prov, t), "google", "/resource", t)
	p2 := "/oauth-redirect-google?state=" + s2

	r2 := httptest.NewRecorder()
	q2, _ := http.NewRequest("GET", p2, nil)
	q2.AddCookie(cookie)
	m0.ServeHTTP(r2, q2)

	if r2.Code != 302 {
		t.Fatalf("should be redirect")
	}

	l2 := r2.HeaderMap["Location"][0]
	if !strings.HasPrefix(l2, "https://accounts.google.com/o/oauth2/auth?client_id=") {
		t.Errorf("redirect should be to google, got: %s", l2)
	}
}

func TestRequireLoginAutoRedirect(t *testing.T) {
	m0 := web.New()

	m1 := web.New()
	m1_sub := web.New()
	m1.Handle("/p/*", m1_sub)

	m2 := web.New()
	m2_sub := web.New()
	m2_sub.Use(gojimw.SubRouter)
	m2.Handle("/p/*", m2_sub)

	tests := []struct {
		mux      *web.Mux
		addToMux *web.Mux
		path     string
		redir    string
	}{
		{m0, m0, "/", "/oauth-redirect-google?state="},
		{m1, m1, "/", "/oauth-redirect-google?state="},
		{m1, m1_sub, "/p/", "/p/oauth-redirect-google?state="},
		{m2, m2, "/p/", "/p/oauth-redirect-google?state="},
		{m2, m2_sub, "/p/", "/p/oauth-redirect-google?state="},
	}

	for i, test := range tests {
		// build oauthmw stuff
		sess := newSession()
		prov := newProvider()
		prov.Path = test.path
		prov.Session = sess
		prov.Configs = map[string]*oauth2.Config{
			"google": newGoogleEndpoint(""),
		}

		// to catch the subrouter test
		if test.addToMux == m2_sub {
			prov.SubRouter = true
		}

		// add middleware
		sessmw := sess.Middleware()
		rlmw := prov.RequireLogin(func() bool {
			return true
		})
		test.addToMux.Use(sessmw)
		test.addToMux.Use(rlmw)

		// run test
		r0 := httptest.NewRecorder()
		q0, _ := http.NewRequest("GET", test.path, nil)
		test.mux.ServeHTTP(r0, q0)
		if r0.Code != 302 {
			t.Fatalf("test %d should be redirected", i)
		}

		l0 := r0.HeaderMap["Location"][0]
		if !strings.HasPrefix(l0, test.redir) {
			t.Errorf("test %d invalid redirect %s", i, l0)
		}

		// remove middleware from mux so they can be reused
		test.addToMux.Abandon(rlmw)
		test.addToMux.Abandon(sessmw)
	}
}

func TestRequireLoginFlow(t *testing.T) {
	// setup test oauth server
	server := httptest.NewServer(newOsinServer())
	defer server.Close()

	// set oauth2context HTTPClient to force oauth2 Exchange to use it
	client := newClient(server.URL)
	oauth2Context = context.WithValue(oauth2Context, oauth2.HTTPClient, client)

	// oauth2 configs for use
	configs := map[string]*oauth2.Config{
		"google":   newGoogleEndpoint(""),
		"facebook": newFacebookEndpoint(""),
		"osin":     newOsinEndpoint(server.URL),
	}

	tests := []struct {
		path string
		req  string
		exp  []string
	}{
		{"/", "/resource", []string{
			"/oauth-redirect-google?state=",
			"/oauth-redirect-facebook?state=",
			"/oauth-redirect-osin?state=",
		}},

		{"/p", "/p/resource", []string{
			"/p/oauth-redirect-google?state=",
			"/p/oauth-redirect-facebook?state=",
			"/p/oauth-redirect-osin?state=",
		}},
	}

	for i, test := range tests {
		// build oauthmw stuff
		prov := newProvider()
		sess := newSession()
		prov.Session = sess
		prov.Path = test.path
		prov.Configs = configs
		prov.TokenLifetime = 1 * time.Minute

		// build mux and add middleware
		m0 := web.New()
		m0.Use(sess.Middleware())
		m0.Use(prov.RequireLogin(func() bool {
			return true
		}))
		m0.Handle("/*", okHandler)

		// do initial request
		r0 := httptest.NewRecorder()
		q0, _ := http.NewRequest("GET", test.req, nil)
		m0.ServeHTTP(r0, q0)

		if r0.Code != 200 {
			t.Errorf("test %d should return 200, got: %d", i, r0.Code)
		}

		cookie := getCookie(r0, t)

		// verify we didn't hit the OK handler
		b0 := r0.Body.String()
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
			// build recorder
			r1 := httptest.NewRecorder()
			q1, _ := http.NewRequest("GET", match[1], nil)
			q1.AddCookie(cookie)
			m0.ServeHTTP(r1, q1)

			if r1.Code != 302 {
				t.Errorf("test %d GET %s should redirect", i, match[1])
			}

			// check redirect location
			l1 := r1.HeaderMap["Location"][0]
			if len(l1) < 1 {
				t.Error("should have redirect location")
			}

			u0, err := url.Parse(l1)
			if err != nil {
				t.Errorf("location did not parse correctly: %s -- %s", err, u0)
			}

			// if this is the local (osin) endpoint, then do actual
			// authorization from osin server
			if strings.HasPrefix(l1, server.URL) {
				// do authorization
				resp, err := client.Get(l1)
				u1 := checkAuthResp(resp, err, t)

				// change path due to hard coded values in
				// osin/example.TestStorage
				u1.Path = test.path + "/oauth-login"

				// setup recorder/request for return (oauth-login)
				r2 := httptest.NewRecorder()
				q2, _ := http.NewRequest("GET", u1.String(), nil)
				q2.AddCookie(cookie)
				m0.ServeHTTP(r2, q2)

				// result should be a redirect back to original resource path
				if r2.Code != 301 {
					t.Fatalf("should be 301 after auth, got: %d", r2.Code)
				}

				// verify redirect resource path is same as original request
				l2 := r2.HeaderMap["Location"][0]
				if test.req != l2 {
					t.Errorf("test %d req path (%s) redir should be same after auth, got: %s", i, test.req, l2)
				}

				// check original resource path now is passed to 'OK' handler
				r3 := httptest.NewRecorder()
				q3, _ := http.NewRequest("GET", test.req, nil)
				q3.AddCookie(cookie)
				m0.ServeHTTP(r3, q3)

				checkOK(fmt.Sprintf("test %d after auth should be OK", i), r3, t)

				// make sure double redemption not possible
				r4 := httptest.NewRecorder()
				q4, _ := http.NewRequest("GET", u1.String(), nil)
				q4.AddCookie(cookie)
				m0.ServeHTTP(r4, q4)
				checkError(500, "already redeemed. try again", r4, t)
			}
		}
	}

	// reset context
	oauth2Context = oauth2.NoContext
}

// test really long resource paths (limit to what securecookie can encode)
func TestInvalidStates(t *testing.T) {
	respath := "/" + strings.Repeat("x", 4096)

	sess := newSession()
	prov := newProvider()
	prov.Path = "/"
	prov.Session = sess
	prov.Configs = map[string]*oauth2.Config{
		"google": newGoogleEndpoint(""),
	}

	m0 := web.New()
	m0.Use(sess.Middleware())
	m0.Use(prov.RequireLogin(func() bool {
		return true
	}))
	m0.Handle("/*", okHandler)

	r0 := httptest.NewRecorder()
	q0, _ := http.NewRequest("GET", respath, nil)
	m0.ServeHTTP(r0, q0)

	checkError(500, "could not encode state for google", r0, t)

	// same test, but with multiple providers
	prov.Configs["facebook"] = newFacebookEndpoint("")

	m1 := web.New()
	m1.Use(sess.Middleware())
	m1.Use(prov.RequireLogin(func() bool {
		return true
	}))

	m1.Handle("/*", okHandler)
	r1 := httptest.NewRecorder()
	q1, _ := http.NewRequest("GET", respath, nil)
	m1.ServeHTTP(r1, q1)

	checkError(500, "could not encode state for facebook (2)", r1, t)
}

func checkStatesCount(prov *Provider, count int, msg string, t *testing.T) {
	mstore, ok := prov.Session.Store.(*sessions.MemoryStore)
	if !ok {
		t.Fatal("session store should be convertible")
	}

	// convert again
	store := map[string]map[string]interface{}(*mstore)
	if len(store) != 1 {
		t.Fatal("store should have exactly one key")
	}

	// loop over store
	for _, item := range store {
		sessStore, ok := item[prov.SessionKey].(Store)
		if !ok {
			t.Fatal("item should be of type Store")
		}

		if len(sessStore.States) != count {
			t.Error(msg)
		}
	}
}

func TestStatesCleanup(t *testing.T) {
	sess := newSession()
	prov := newProvider()
	prov.Path = "/"
	prov.Session = sess
	prov.SessionLifetime = 1 * time.Second
	prov.Configs = map[string]*oauth2.Config{
		"google": newGoogleEndpoint(""),
	}
	prov.checkDefaults()

	m0 := web.New()
	m0.Use(sess.Middleware())
	m0.Use(prov.Login(func() bool {
		return true
	}))
	m0.Handle("/ok", okHandler)

	// do initial request
	r0 := httptest.NewRecorder()
	q0, _ := http.NewRequest("GET", "/ok", nil)
	m0.ServeHTTP(r0, q0)

	if r0.Code != 200 {
		t.Errorf("should return 200, got: %d", r0.Code)
	}

	cookie := getCookie(r0, t)

	// add a lot of states
	for i := 0; i < 2*DefaultMaxStates; i++ {
		s1 := encodeState(&prov, getSid(&prov, t), "google", "/resource", t)
		p1 := "/oauth-redirect-google?state=" + s1

		// send request
		r1 := httptest.NewRecorder()
		q1, _ := http.NewRequest("GET", p1, nil)
		q1.AddCookie(cookie)
		m0.ServeHTTP(r1, q1)

		if r1.Code != 302 {
			t.Fatalf("code should be 302, got: %d -- %s", r1.Code, r1.Body.String())
		}

		l1 := r1.HeaderMap["Location"][0]
		if !strings.HasPrefix(l1, "https://accounts.google.com/o/oauth2/auth?client_id=") {
			t.Errorf("redirect should be to google, got: %s", l1)
		}
	}

	checkStatesCount(&prov, 2*DefaultMaxStates, "states count should be 2*DefaultMaxStates", t)

	// expire all states
	setStatesExpiration(&prov, time.Now().Add(-1*time.Hour), t)

	// kick cleanup
	r2 := httptest.NewRecorder()
	q2, _ := http.NewRequest("GET", "/ok", nil)
	q2.AddCookie(cookie)
	m0.ServeHTTP(r2, q2)

	checkStatesCount(&prov, 0, "states should be empty after cleanup", t)
}

func TestRedirectErrors(t *testing.T) {
	sess := newSession()
	prov := newProvider()
	prov.Session = sess
	prov.Path = "/"
	prov.Configs = map[string]*oauth2.Config{
		"google":   newGoogleEndpoint(""),
		"facebook": newFacebookEndpoint(""),
	}
	prov.checkDefaults()

	m0 := web.New()
	m0.Use(sess.Middleware())
	m0.Use(prov.Login(func() bool {
		return true
	}))
	m0.Handle("/ok", okHandler)

	//--------------------------------------
	// initial setup
	r0 := httptest.NewRecorder()
	q0, _ := http.NewRequest("GET", "/ok", nil)
	m0.ServeHTTP(r0, q0)
	checkOK("should fall to okHandler", r0, t)

	// grab cookie from request
	cookie := getCookie(r0, t)
	//--------------------------------------

	//--------------------------------------
	state := encodeState(&prov, getSid(&prov, t), "google", "/resource", t)
	//--------------------------------------

	//--------------------------------------
	// check bad provider
	r1 := httptest.NewRecorder()
	q1, _ := http.NewRequest("GET", "/oauth-redirect-bad?state="+state, nil)
	q1.AddCookie(cookie)
	m0.ServeHTTP(r1, q1)
	checkError(500, "invalid provider", r1, t)
	//--------------------------------------

	//--------------------------------------
	// check forged sid
	s01 := encodeState(&prov, "", "google", "/resource", t)
	r01 := httptest.NewRecorder()
	q01, _ := http.NewRequest("GET", "/oauth-redirect-google?state="+s01, nil)
	q01.AddCookie(cookie)
	m0.ServeHTTP(r01, q01)
	checkError(500, "forged sid in redirect", r01, t)
	//--------------------------------------

	//--------------------------------------
	// test forged provider
	r2 := httptest.NewRecorder()
	q2, _ := http.NewRequest("GET", "/oauth-redirect-facebook?state="+state, nil)
	q2.AddCookie(cookie)
	m0.ServeHTTP(r2, q2)
	checkError(500, "forged provider in redirect", r2, t)
	//--------------------------------------
}

func setStatesExpiration(prov *Provider, expiration time.Time, t *testing.T) {
	mstore, ok := prov.Session.Store.(*sessions.MemoryStore)
	if !ok {
		t.Fatal("session store should be convertible")
	}

	// convert again
	store := map[string]map[string]interface{}(*mstore)
	if len(store) != 1 {
		t.Fatal("store should have exactly one key")
	}

	// loop over store
	for _, item := range store {
		sessStore, ok := item[prov.SessionKey].(Store)
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

func addBadState(prov *Provider, state map[string]string, t *testing.T) string {
	badState := encodeBadState(prov, state, t)

	key := fmt.Sprintf("%x", md5.Sum([]byte(badState)))

	mstore, ok := prov.Session.Store.(*sessions.MemoryStore)
	if !ok {
		t.Fatal("session store should be convertible")
	}

	// convert again
	store := map[string]map[string]interface{}(*mstore)
	if len(store) != 1 {
		t.Fatal("store should have exactly one key")
	}

	// loop over store
	for _, item := range store {
		sessStore, ok := item[prov.SessionKey].(Store)
		if !ok {
			t.Fatal("item should be of type Store")
		}
		sessStore.States[key] = StoreState{
			Provider: "osin",
		}
	}

	return badState
}

func TestReturnErrors(t *testing.T) {
	// setup test oauth server
	server := httptest.NewServer(newOsinServer())
	defer server.Close()

	// set oauth2context HTTPClient to force oauth2 Exchange to use it
	client := newClient(server.URL)
	oauth2Context = context.WithValue(oauth2Context, oauth2.HTTPClient, client)

	// build oauthmw stuff
	prov := newProvider()
	sess := newSession()
	prov.Session = sess
	prov.Path = "/"
	prov.Configs = map[string]*oauth2.Config{
		"osin": newOsinEndpoint(server.URL),
	}
	prov.checkDefaults()

	// build mux and add middleware
	m0 := web.New()
	m0.Use(sess.Middleware())
	m0.Use(prov.RequireLogin(func() bool {
		return true
	}))
	m0.Handle("/*", okHandler)

	//--------------------------------------
	// do basic request
	r00 := httptest.NewRecorder()
	q00, _ := http.NewRequest("GET", "/", nil)
	m0.ServeHTTP(r00, q00)
	if r00.Code != 302 {
		t.Fatalf("should 302 redirect, got: %d", r00.Code)
	}

	cookie := getCookie(r00, t)
	//--------------------------------------

	//--------------------------------------
	// do setup request
	s0 := encodeState(&prov, getSid(&prov, t), "osin", "/resource", t)
	r0 := httptest.NewRecorder()
	q0, _ := http.NewRequest("GET", "/oauth-redirect-osin?state="+s0, nil)
	q0.AddCookie(cookie)
	m0.ServeHTTP(r0, q0)

	if r0.Code != 302 {
		t.Fatalf("should 302 redirect, got: %d", r0.Code)
	}

	// check redirect
	l0 := r0.HeaderMap["Location"][0]
	if len(l0) < 1 {
		t.Error("should have redirect location")
	}

	u0, err := url.Parse(l0)
	if err != nil {
		t.Errorf("location did not parse correctly: %s -- %s", err, u0)
	}

	// verify pointing to osin server
	if !strings.HasPrefix(l0, server.URL) {
		t.Fatalf("redir location should be server.URL, got: %s", l0)
	}
	//--------------------------------------

	//--------------------------------------
	// change path due to hard coded values in
	// osin/example.TestStorage
	resp, err := client.Get(l0)
	u1 := checkAuthResp(resp, err, t)
	u1.Path = "/oauth-login"
	//--------------------------------------

	//--------------------------------------
	// send a bad code
	p1 := fmt.Sprintf(
		"%s?code=%s&state=%s",
		u1.Path,
		"badcode",
		s0,
	)

	// check that state is not there
	r1 := httptest.NewRecorder()
	q1, _ := http.NewRequest("GET", p1, nil)
	q1.AddCookie(cookie)
	m0.ServeHTTP(r1, q1)
	checkError(500, "could not do exchange with osin", r1, t)
	//--------------------------------------

	//--------------------------------------
	// get bad (already expired) token from server
	p2 := fmt.Sprintf(
		"%s?code=%s&state=%s",
		u1.Path,
		url.QueryEscape(u1.Query().Get("code")),
		encodeState(&prov, getSid(&prov, t), "osin", "/resource", t),
	)

	// check that state is not there
	r2 := httptest.NewRecorder()
	q2, _ := http.NewRequest("GET", p2, nil)
	q2.AddCookie(cookie)
	m0.ServeHTTP(r2, q2)
	checkError(500, "state not found in session", r2, t)
	//--------------------------------------

	//--------------------------------------
	// check expired state
	setStatesExpiration(&prov, time.Now().Add(-1*time.Hour), t)
	r3 := httptest.NewRecorder()
	q3, _ := http.NewRequest("GET", u1.String(), nil)
	q3.AddCookie(cookie)
	m0.ServeHTTP(r3, q3)
	checkError(500, "request expired. try again", r3, t)
	setStatesExpiration(&prov, time.Now().Add(1*time.Hour), t)
	//--------------------------------------

	//--------------------------------------
	// check bad sid in state
	badState04 := addBadState(&prov, map[string]string{
		"sid":      "",
		"provider": "osin",
		"resource": "/resource",
	}, t)

	p04 := fmt.Sprintf(
		"%s?code=%s&state=%s",
		u1.Path,
		u1.Query().Get("code"),
		badState04,
	)
	r04 := httptest.NewRecorder()
	q04, _ := http.NewRequest("GET", p04, nil)
	q04.AddCookie(cookie)
	m0.ServeHTTP(r04, q04)
	checkError(500, "forged sid in return", r04, t)
	//--------------------------------------

	//--------------------------------------
	// check bad provider in state
	badState4 := addBadState(&prov, map[string]string{
		"sid":      getSid(&prov, t),
		"provider": "",
		"resource": "/resource",
	}, t)

	p4 := fmt.Sprintf(
		"%s?code=%s&state=%s",
		u1.Path,
		u1.Query().Get("code"),
		badState4,
	)
	r4 := httptest.NewRecorder()
	q4, _ := http.NewRequest("GET", p4, nil)
	q4.AddCookie(cookie)
	m0.ServeHTTP(r4, q4)
	checkError(500, "invalid provider", r4, t)
	//--------------------------------------

	//--------------------------------------
	// check missing resource in state
	badState5 := addBadState(&prov, map[string]string{
		"sid":      getSid(&prov, t),
		"provider": "osin",
	}, t)

	p5 := fmt.Sprintf(
		"%s?code=%s&state=%s",
		u1.Path,
		u1.Query().Get("code"),
		badState5,
	)
	r5 := httptest.NewRecorder()
	q5, _ := http.NewRequest("GET", p5, nil)
	q5.AddCookie(cookie)
	m0.ServeHTTP(r5, q5)
	checkError(500, "invalid resource", r5, t)
	//--------------------------------------

	//--------------------------------------
	// send a bad token
	p6 := fmt.Sprintf(
		"%s?code=%s&state=%s",
		u1.Path,
		"badtoken",
		s0,
	)

	// check that state is not there
	r6 := httptest.NewRecorder()
	q6, _ := http.NewRequest("GET", p6, nil)
	q6.AddCookie(cookie)
	m0.ServeHTTP(r6, q6)
	checkError(403, http.StatusText(403), r6, t)
	//--------------------------------------

	// reset context
	oauth2Context = oauth2.NoContext
}

// gets the item in the session, and returns it
// corrupts the actual item with passed item
func swapSessionStore(prov *Provider, obj interface{}, doErr bool, t *testing.T) interface{} {
	mstore, ok := prov.Session.Store.(*sessions.MemoryStore)
	if !ok {
		t.Fatal("session store should be convertible")
	}

	// convert again
	store := map[string]map[string]interface{}(*mstore)
	if len(store) != 1 {
		t.Fatal("store should have exactly one key")
	}

	// loop over store
	var sessStore interface{} = nil
	for _, item := range store {
		sessStore, ok = item[prov.SessionKey].(Store)
		if !ok && doErr {
			t.Fatal("item should be of type Store")
		}

		item[prov.SessionKey] = obj
	}

	return sessStore
}

func TestSessionStore(t *testing.T) {
	sess := newSession()
	prov := newProvider()
	prov.Session = sess
	prov.Path = "/"
	prov.Configs = map[string]*oauth2.Config{
		"google": newGoogleEndpoint(""),
	}
	prov.checkDefaults()

	m0 := web.New()
	m0.Use(sess.Middleware())
	m0.Use(prov.Login(func() bool {
		return true
	}))
	m0.Handle("/ok", okHandler)

	r0 := httptest.NewRecorder()
	q0, _ := http.NewRequest("GET", "/ok", nil)
	m0.ServeHTTP(r0, q0)
	checkOK("should fall to okHandler", r0, t)

	// grab cookie from request
	cookie := getCookie(r0, t)

	// corrupt session store
	obj0 := swapSessionStore(&prov, "baddata", true, t)
	_, ok := obj0.(Store)
	if !ok {
		t.Error("item in session should be store")
	}

	// send another request
	r1 := httptest.NewRecorder()
	q1, _ := http.NewRequest("GET", "/ok", nil)
	q1.AddCookie(cookie)
	m0.ServeHTTP(r1, q1)
	checkOK("should fall to okHandler", r1, t)

	// check that store is no longer corrupted
	obj1 := swapSessionStore(&prov, obj0, true, t)
	_, ok = obj1.(Store)
	if !ok {
		t.Error("store should have been fixed")
	}

	// test nil token
	_ = swapSessionStore(&prov, Store{Token: nil}, false, t)
	r2 := httptest.NewRecorder()
	q2, _ := http.NewRequest("GET", "/ok", nil)
	q2.AddCookie(cookie)
	m0.ServeHTTP(r2, q2)
	checkOK("should fall to okHandler", r2, t)

	// test expired token
	m1 := web.New()
	m1.Use(sess.Middleware())
	m1.Use(prov.RequireLogin(func() bool {
		return true
	}))
	m1.Handle("/ok", okHandler)

	r3 := httptest.NewRecorder()
	q3, _ := http.NewRequest("GET", "/ok", nil)
	q3.AddCookie(cookie)
	m1.ServeHTTP(r3, q3)
	if r3.Code != 302 {
		t.Fatalf("should be redirect")
	}

	// create a token
	tok3 := oauth2.Token{
		AccessToken: "access",
		TokenType:   "bearer",
		Expiry:      time.Now().Add(1 * time.Hour),
	}

	// put token in session
	_ = swapSessionStore(&prov, Store{
		Token:  &tok3,
		States: make(map[string]StoreState),
	}, true, t)

	// test that there is access
	r4 := httptest.NewRecorder()
	q4, _ := http.NewRequest("GET", "/ok", nil)
	q4.AddCookie(cookie)
	m1.ServeHTTP(r4, q4)
	checkOK("should fall to okHandler", r4, t)

	// set token as expired
	tok3.Expiry = time.Now().Add(-1 * time.Hour)

	// test that access has been revoked
	r5 := httptest.NewRecorder()
	q5, _ := http.NewRequest("GET", "/ok", nil)
	q5.AddCookie(cookie)
	m1.ServeHTTP(r5, q5)
	if r5.Code != 302 {
		t.Error("should be redirect")
	}
}

// test multiple / different sub paths. each should still require login
// even if another has already been authenticated
/*func TestMultipleMiddlewarePaths(t *testing.T) {

}*/
