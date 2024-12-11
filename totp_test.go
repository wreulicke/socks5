package main

import (
	"testing"

	"github.com/pquerna/otp/totp"
)

// FIXME: delete this
func TestTotp(t *testing.T) {
	// This is a test function.
	// use https://github.com/pquerna/otp

	// Create a new TOTP object
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "socks5",
		AccountName: "test",
		Secret:      []byte("test"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(key.URL())
	// image, err := key.Image(200, 200)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// f, err := os.Create("qrcode.png")
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// defer f.Close()
	// err = png.Encode(f, image)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	t.Log("TOTP:", key.Secret())

}
