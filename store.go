package oauthmw

import (
	"encoding/gob"
	"time"

	"golang.org/x/oauth2"
)

// Store is the object used by oauthmw in the session.
type Store struct {
	// Provider name of token.
	Provider string

	// Token is redeemed oauth2 token.
	Token *oauth2.Token

	// States are the passed states sent to oauth2 providers.
	States map[string]StoreState
}

// StoreState is storage for a passed oauth2 in a session.
type StoreState struct {
	// Provider name of state.
	Provider string

	// Expiration is when the state expires.
	Expiration time.Time

	// Redeemed indicates whether or not the state has been previously redeemed.
	Redeemed bool
}

func init() {
	// register oauthmw stores for use by ymichael/sessions gob.encode/decode
	gob.RegisterName("knq.oauthmw.Store", Store{})
	gob.RegisterName("knq.oauthmw.StoreState", StoreState{})
}
