package main

import (
	"flag"
	"io"
	"log"
	"net/http"

	"golang.org/x/net/proxy"
)

var (
	flagPassword = flag.String("password", "test", "password")
)

func mainInternal() error {
	p, err := proxy.SOCKS5("tcp", "127.0.0.1:10080", &proxy.Auth{
		User:     "test",
		Password: *flagPassword,
	}, proxy.Direct)
	if err != nil {
		return err
	}

	client := http.DefaultClient
	client.Transport = &http.Transport{
		Dial: p.Dial,
	}

	resp, err := client.Get("https://example.com")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	log.Println("Response status:", resp.Status)
	bs, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	log.Println("Response body:", string(bs))

	return nil
}

func main() {
	flag.Parse()
	if err := mainInternal(); err != nil {
		log.Fatal(err)
	}
}
