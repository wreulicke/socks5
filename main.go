package main

import (
	"context"
	"crypto/rand"
	"encoding/base32"
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

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
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
	q *Queries
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
		if m == byte(AuthMethodUsernamePassword) {
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
	err = c.authenticateByUsernameAndPassword(username, password)
	if err != nil {
		err = fmt.Errorf("failed to authenticate: %w", err)
		_, resErr := c.Write([]byte{1, 0})
		if resErr != nil {
			return fmt.Errorf("failed to write authentication response: %w: %w", resErr, err)
		}
		return err
	}

	_, err = c.Write([]byte{1, 0})
	c.state = stateRequest
	return err
}

func (c *socks5Conn) authenticateByUsernameAndPassword(username, password string) error {
	h, err := c.q.GetPasswordHash(context.TODO(), username)
	if err != nil {
		return fmt.Errorf("failed to get password hash: %w", err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(h.PasswordHash), []byte(password))
	if err != nil {
		return fmt.Errorf("failed to compare password hash: %w", err)
	}

	return nil
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

func (c *socks5Conn) Start(ctx context.Context) {
	_ = c.Conn.SetDeadline(time.Now().Add(time.Second * 5))
	defer c.Close()

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
			c.state = stateClosed
		default:
		}

		switch c.state {
		case stateMethodSelection:
			err := c.handleMethodSelection()
			if err != nil {
				log.Println(err)
				return
			}
		case stateAuthenticating:
			err := c.handleAuthentication()
			if err != nil {
				log.Println(err)
				return
			}
		case stateRequest:
			err := c.handleRequest()
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
					_, err := io.Copy(c.remote, c)
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
					_, err := io.Copy(c, c.remote)
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
func startServer(ctx context.Context, ln *net.TCPListener, queries *Queries) {
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

		socks5Conn := &socks5Conn{
			q:     queries,
			Conn:  conn,
			state: stateMethodSelection,
		}
		go socks5Conn.Start(ctx)
	}
}

func initUserPasswordHashes(ctx context.Context, queries *Queries) error {
	initialPassword, initialPasswordHash, err := generateInitialPasswordHash()
	if err != nil {
		return fmt.Errorf("failed to generate initial password: %w", err)
	}
	_, err = queries.SetPasswordHash(ctx, SetPasswordHashParams{
		Username:     "test",
		PasswordHash: initialPasswordHash,
	})

	var pgError *pgconn.PgError
	if errors.As(err, &pgError) && pgError.Code == "23505" {
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to set initial password hash: %w", err)
	}

	log.Printf("Initialized user with password: %s", initialPassword)

	return nil
}

func generateInitialPasswordHash() (string, string, error) {
	bs := make([]byte, 32)
	_, err := rand.Read(bs)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	initialPassword := base32.StdEncoding.EncodeToString(bs)
	hash, err := bcrypt.GenerateFromPassword([]byte(initialPassword), bcrypt.DefaultCost)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate password hash: %w", err)
	}

	return initialPassword, string(hash), nil
}

func mainInternal() error {
	addr := os.Getenv("SOCKS5_ADDR")
	if addr == "" {
		addr = ":10080"
	}
	c, err := pgxpool.ParseConfig("postgres://root:root@localhost:15432/root?sslmode=disable")
	if err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(context.TODO(), c)
	if err != nil {
		return fmt.Errorf("failed to create connection pool: %w", err)
	}
	queries := New(pool)

	err = initUserPasswordHashes(context.TODO(), queries)
	if err != nil {
		return fmt.Errorf("failed to initialize user password hashes: %w", err)
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
		startServer(ctx, ln, queries)
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
