package oauthmw

import (
	"encoding/gob"
	"time"

	//"github.com/knq/sessionmw/jsonstore"

	"golang.org/x/oauth2"
)

// Store is the object used by oauthmw in the session.
type Store struct {
	// Provider name of token.
	Provider string `json:"provider"`

	// Token is redeemed oauth2 token.
	Token *oauth2.Token `json:"token,omitempty"`

	// States are the passed states sent to oauth2 providers.
	States map[string]StoreState `json:"states"`
}

// StoreState is storage for a passed oauth2 in a session.
type StoreState struct {
	// Provider name of state.
	Provider string `json:"provider"`

	// Expiration is when the state expires.
	Expiration time.Time `json:"expiration"`

	// Redeemed indicates whether or not the state has been previously redeemed.
	Redeemed bool `json:"redeemed"`
}

func init() {
	// register oauthmw stores for use by gob.encode/decode (ie various binary sessionmw.Store types)
	gob.RegisterName("knq.oauthmw.Store", Store{})
	gob.RegisterName("knq.oauthmw.StoreState", StoreState{})

	// register oauthmw for use with jsonstore
	//jsonstore.RegisterSchema("knq.oauthmw.Store", Store{})
	//jsonstore.RegisterSchema("knq.oauthmw.StoreState", StoreState{})
}
