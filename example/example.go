// example.go
package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/knq/oauthmw"
	"github.com/ymichael/sessions"
	"github.com/zenazn/goji"
	"github.com/zenazn/goji/web"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/google"
)

func main() {
	// create session
	sess := &sessions.SessionOptions{
		Name:      "mySessionId",
		Secret:    "K7qv0EG3tBvDXCXhPcrRmdceS0RCMm8B",
		ObjEnvKey: "sessionObject",
		SidEnvKey: "sessionId",
		Store:     &sessions.MemoryStore{},
		CookieOptions: &sessions.CookieOptions{
			Path:     "/",
			MaxAge:   0,
			HttpOnly: true,
			Secure:   false,
		},
	}

	// create oauthmw provider
	prov := oauthmw.Provider{
		Secret:      "NzfWi6Sj3gQ8cEUmu3f705bGLyGJ6Xh3",
		BlockSecret: "LxUpc1GPFKFQ5tMpciQAgv5o80yuzBzH",
		Session:     sess,
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

	// add middleware
	goji.Use(sess.Middleware())
	goji.Use(prov.RequireLogin(func(provName string, config *oauth2.Config, token *oauth2.Token) (string, bool) {
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
	goji.Handle("/*", func(c web.C, w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "this is my protected area! path: %s", c.URLParams["*"])
	})

	goji.Serve()
}
