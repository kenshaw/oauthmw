package oauthmw

import (
	"encoding/gob"
	"time"

	"golang.org/x/oauth2"
)

// Store is the object used by oauthmw in the session.
type Store struct {
	Token  *oauth2.Token
	States map[string]StoreState
}

// StoreState is storage for a passed oauth2 in a session.
type StoreState struct {
	Provider   string
	Expiration time.Time
	Redeemed   bool
}

func init() {
	// register oauthmw stores for use by ymichael/sessions gob.encode/decode
	gob.Register(Store{})
	gob.Register(StoreState{})
}
