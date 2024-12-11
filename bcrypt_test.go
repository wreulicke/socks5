package main

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// FIXME: delete this
func TestBcrypt(t *testing.T) {
	// This is a test function.
	// use https://pkg.go.dev/golang.org/x/crypto/bcrypt
	bcryptPassword, err := bcrypt.GenerateFromPassword([]byte("test"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(bcryptPassword))

	err = bcrypt.CompareHashAndPassword(bcryptPassword, []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
}
