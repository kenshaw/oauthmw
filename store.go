package oauthmw

import (
	"encoding/gob"
	"time"

	"golang.org/x/oauth2"
)

// Middleware session store.
type Store struct {
	Token  *oauth2.Token
	States map[string]StoreState
}

// Passed oauth2 state store.
type StoreState struct {
	Provider   string
	Expiration time.Time
	Redeemed   bool
}

// register above types for ymichael/sessions gob.encode/decode
func init() {
	gob.Register(Store{})
	gob.Register(StoreState{})
}
