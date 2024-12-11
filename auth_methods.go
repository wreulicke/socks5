package main

type AuthMethod byte

const (
	AuthMethodNoAuth AuthMethod = iota
	AuthMethodGSSAPI
	AuthMethodUsernamePassword
	AuthMethod2FA          = 0x7f
	AuthMethodNoAcceptable = 0xff
)
