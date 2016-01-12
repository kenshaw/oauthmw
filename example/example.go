// example/example.go
package main

import (
	"fmt"
	"net/http"
	"os"

	"golang.org/x/net/context"

	"goji.io"
	"goji.io/pat"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/google"

	"github.com/knq/kv"
	"github.com/knq/oauthmw"
	"github.com/knq/sessionmw"
)

func main() {
	// create session
	sess := &sessionmw.Config{
		Name:        "mySessionCookie",
		Secret:      []byte("K7qv0EG3tBvDXCXhPcrRmdceS0RCMm8B"),
		BlockSecret: []byte("xUYUQ4seHVFFhJ2iInWpnfPHrYomVeaf"),
		Store:       kv.NewMemStore(),
	}

	// create oauthmw provider
	prov := oauthmw.Provider{
		Secret:      []byte("NzfWi6Sj3gQ8cEUmu3f705bGLyGJ6Xh3"),
		BlockSecret: []byte("LxUpc1GPFKFQ5tMpciQAgv5o80yuzBzH"),
		Path:        "/",
		Configs: map[string]*oauth2.Config{
			"google": {
				Endpoint:     google.Endpoint,
				ClientID:     os.Getenv("OAUTHMW_GOOGLEID"),
				ClientSecret: os.Getenv("OAUTHMW_GOOGLESECRET"),
				RedirectURL:  "http://localhost:8000/oauth-login",
				Scopes: []string{
					"https://www.googleapis.com/auth/plus.login",
					"https://www.googleapis.com/auth/userinfo.email",
				},
			},
			"facebook": {
				Endpoint:     facebook.Endpoint,
				ClientID:     os.Getenv("OAUTHMW_FACEBOOKID"),
				ClientSecret: os.Getenv("OAUTHMW_FACEBOOKSECRET"),
				RedirectURL:  "http://localhost:8000/oauth-login",
				Scopes: []string{
					"public_profile,email",
				},
			},
		},
	}

	mux := goji.NewMux()

	// add middleware
	mux.UseC(sess.Handler)
	mux.UseC(prov.RequireLogin(func(provName string, config *oauth2.Config, token *oauth2.Token) (string, bool) {
		// this is a super fancy check callback function
		switch provName {
		case "facebook":
			// client := config.Client(context, token)
		case "google":
			// client := config.Client(context, token)

		default:
			return "bad provider!", false
		}

		// no errors encountered
		return "", true
	}))

	// simple demonstration handler
	mux.HandleFuncC(pat.Get("/*"), func(ctxt context.Context, res http.ResponseWriter, req *http.Request) {
		http.Error(res, fmt.Sprintf("this is my protected area! path: %+v", ctxt), http.StatusOK)
	})

	// serve
	http.ListenAndServe(":8000", mux)
}
