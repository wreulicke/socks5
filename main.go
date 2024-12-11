package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

type state int

const (
	stateMethodSelection state = iota
	stateAuthenticating
	stateRequest
	stateEstablished
	stateConnecting
	stateClosed
)

type socks5Conn struct {
	net.Conn

	remote net.Conn
	state  state
}

func (c *socks5Conn) handleMethodSelection() error {
	buf := make([]byte, 2)
	_, err := c.Read(buf)
	if err != nil {
		return err
	}

	if buf[0] != 5 {
		return errors.New("invalid version")
	}

	nMethods := int(buf[1])
	methods := make([]byte, nMethods)
	_, err = c.Read(methods)
	if err != nil {
		return fmt.Errorf("failed to read methods: %w", err)
	}

	for _, m := range methods {
		if m == 2 {
			_, err = c.Write([]byte{5, 2})
			if err != nil {
				return fmt.Errorf("failed to write method selection response: %w", err)
			}
			c.state = stateAuthenticating
			return nil
		}
	}

	return errors.New("no supported method found")
}

func (c *socks5Conn) handleAuthentication() error {
	buf := make([]byte, 2)

	n, err := c.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read authentication request: %w", err)
	}

	if n < 2 {
		return errors.New("invalid authentication request")
	}

	if buf[0] != 1 {
		return errors.New("invalid version")
	}

	// read username
	usernameLen := int(buf[1])
	buf = make([]byte, usernameLen)
	n, err = c.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read username: %w", err)
	}

	if n < usernameLen {
		return errors.New("invalid username")
	}

	username := string(buf)

	// read password
	n, err = c.Read(buf[:1])
	if err != nil {
		return fmt.Errorf("failed to read password length: %w", err)
	}

	if n < 1 {
		return errors.New("invalid password length")
	}

	passwordLen := int(buf[0])
	buf = make([]byte, passwordLen)
	n, err = c.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	if n < passwordLen {
		return errors.New("invalid password")
	}

	password := string(buf)

	// TODO implement authentication correctly
	log.Println("authenticating...", username, password)

	_, err = c.Write([]byte{1, 0})
	c.state = stateRequest
	return err
}

func (c *socks5Conn) handleRequest() error {
	buf := make([]byte, 1024)
	n, err := c.Read(buf[:4])

	if err != nil {
		return fmt.Errorf("failed to read request: %w", err)
	}

	if n < 4 {
		return errors.New("invalid request")
	}

	if buf[0] != 5 {
		return errors.New("invalid version")
	}

	if buf[1] != 1 {
		return errors.New("unsupported command")
	}

	if buf[2] != 0 {
		return errors.New("invalid reserved field")
	}

	var host string
	switch buf[3] {
	case 1:
		n, err = c.Read(buf[:4])
		if err != nil {
			return fmt.Errorf("failed to read IPv4 address: %w", err)
		}
		if n < 4 {
			return errors.New("invalid IPv4 address")
		}
		host = net.IP(buf[:4]).String()
	case 3:
		n, err = c.Read(buf[:1])
		if err != nil {
			return fmt.Errorf("failed to read FQDN length: %w", err)
		}
		if n < 1 {
			return errors.New("invalid FQDN length")
		}
		fqdnLen := int(buf[0])
		n, err = c.Read(buf[:fqdnLen])
		if err != nil {
			return fmt.Errorf("failed to read FQDN: %w", err)
		}
		if n < fqdnLen {
			return errors.New("invalid FQDN")
		}
		host = string(buf[:fqdnLen])
	case 4:
		n, err = c.Read(buf[:16])
		if err != nil {
			return fmt.Errorf("failed to read IPv6 address: %w", err)
		}

		if n < 16 {
			return errors.New("invalid IPv6 address")
		}
		host = net.IP(buf[:16]).String()
	default:
		return errors.New("unsupported address type")
	}

	n, err = c.Read(buf[:2])
	if err != nil {
		return fmt.Errorf("failed to read port: %w", err)
	}

	if n < 2 {
		return errors.New("invalid port")
	}

	port := int(buf[0])<<8 + int(buf[1])

	log.Printf("connecting to %s:%d", host, port)

	c.remote, err = net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("failed to connect to remote: %w", err)
	}

	_, err = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	if err != nil {
		return fmt.Errorf("failed to write response: %w", err)
	}

	c.state = stateEstablished
	return nil
}

func (c *socks5Conn) Close() error {
	if c.remote != nil {
		c.remote.Close()
	}
	return c.Conn.Close()
}

func socks5handler(ctx context.Context, conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(time.Second * 5))
	sock := &socks5Conn{Conn: conn, state: stateMethodSelection}
	defer sock.Close()

	errChan := make(chan error, 2)
	for {
		select {
		case <-ctx.Done():
			return
		case err := <-errChan:
			var opErr *net.OpError
			if errors.As(err, &opErr) && opErr.Timeout() {
				log.Println("closing due to timeout")
			} else if err != io.EOF {
				log.Println("closing due to error:", err)
			}
			sock.state = stateClosed
		default:
		}

		switch sock.state {
		case stateMethodSelection:
			err := sock.handleMethodSelection()
			if err != nil {
				log.Println(err)
				return
			}
		case stateAuthenticating:
			err := sock.handleAuthentication()
			if err != nil {
				log.Println(err)
				return
			}
		case stateRequest:
			err := sock.handleRequest()
			if err != nil {
				log.Println(err)
				return
			}
		case stateEstablished:
			// TODO reduce goroutines
			go func() {
				for {
					select {
					case <-ctx.Done():
						return
					default:
					}
					_, err := io.Copy(sock.remote, sock)
					if err != nil {
						errChan <- err
						return
					}
				}
			}()
			go func() {
				for {
					select {
					case <-ctx.Done():
						return
					default:
					}
					_, err := io.Copy(sock, sock.remote)
					if err != nil {
						errChan <- err
						return
					}
				}
			}()
		case stateClosed:
			return
		}
	}

}
func startServer(ctx context.Context, ln *net.TCPListener) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		err := ln.SetDeadline(time.Now().Add(time.Second * 10))
		if err != nil {
			log.Println(err)
			continue
		}

		conn, err := ln.Accept()
		var opErr *net.OpError
		if errors.As(err, &opErr) && opErr.Timeout() {
			// log.Println("timeout") debug
			continue
		}
		if err != nil {
			log.Println(err)
			continue
		}

		go socks5handler(ctx, conn)
	}
}

func mainInternal() error {
	addr := os.Getenv("SOCKS5_ADDR")
	if addr == "" {
		addr = ":10080"
	}

	log.Printf("Starting server... %s", addr)
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)

	if err != nil {
		return err
	}

	ln, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return err
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		startServer(ctx, ln)
		log.Println("Server stopped.")
	}()

	defer func(cancel context.CancelFunc) {
		cancel()
		log.Println("Waiting for server to stop...")
		<-done
	}(cancel)

	ctx, cancel = signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()
	<-ctx.Done()

	log.Println("Shutting down...")

	return nil
}

func main() {
	if err := mainInternal(); err != nil {
		log.Fatal(err)
	}
}
