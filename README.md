# About oauthmw [![Build Status](https://travis-ci.org/knq/oauthmw.svg)](https://travis-ci.org/knq/oauthmw) [![Coverage Status](https://coveralls.io/repos/knq/oauthmw/badge.svg?branch=master&service=github)](https://coveralls.io/github/knq/oauthmw?branch=master) #

A [Goji](https://goji.io/) middleware package for handling OAuth2.0 login
flows.

## Installation ##

Install the package via the following:

    go get -u github.com/knq/oauthmw

## Usage ##

Please see [the GoDoc API page](http://godoc.org/github.com/knq/oauthmw) for a
full API listing.

The oauthmw package can be used similarly to the following:

```go
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
        Name:          "mySessionId",
        Secret:        "K7qv0EG3tBvDXCXhPcrRmdceS0RCMm8B",
        ObjEnvKey:     "sessionObject",
        SidEnvKey:     "sessionId",
        Store:         &sessions.MemoryStore{},
        CookieOptions: &sessions.CookieOptions{"/", 0, true, false},
    }

    // create oauthmw provider
    prov := oauthmw.Provider{
        Secret:      "NzfWi6Sj3gQ8cEUmu3f705bGLyGJ6Xh3",
        BlockSecret: "LxUpc1GPFKFQ5tMpciQAgv5o80yuzBzH",
        Session:     sess,
        Path:        "/",
        Configs: map[string]*oauth2.Config{
            "google": &oauth2.Config{
                Endpoint:     google.Endpoint,
                ClientID:     os.Getenv("OAUTHMW_GOOGLEID"),
                ClientSecret: os.Getenv("OAUTHMW_GOOGLESECRET"),
                RedirectURL:  "http://localhost:8000/oauth-login",
                Scopes: []string{
                    "https://www.googleapis.com/auth/plus.login",
                    "https://www.googleapis.com/auth/userinfo.email",
                },
            },
            "facebook": &oauth2.Config{
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
    goji.Use(prov.RequireLogin(func() bool {
        // this is a super fancy check callback function
        return true
    }))

    // simple demonstration handler
    goji.Handle("/*", func(c web.C, w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, "this is my protected area! path: %s", c.URLParams["*"])
    })

    goji.Serve()
}
```
