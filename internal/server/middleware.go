// Package server implements Sentinel's two HTTP surfaces: the client-facing
// rate-limit decision API and the admin configuration/observability API.
package server

import (
	"log/slog"
	"net"
	"net/http"
	"sync"
)

// limitListener wraps a net.Listener so that at most `max` connections can
// be simultaneously open through it. This is a small hand-rolled
// substitute for golang.org/x/net/netutil.LimitListener (the sandbox this
// was built in had no network access to `go get` golang.org/x/net), used
// for NFR3.2 connection-exhaustion protection.
type limitListener struct {
	net.Listener
	sem chan struct{}
}

// LimitListener returns a Listener that accepts at most `max` simultaneous
// connections from the given Listener. If max <= 0, l is returned
// unmodified (no limit applied).
func LimitListener(l net.Listener, max int) net.Listener {
	if max <= 0 {
		return l
	}
	return &limitListener{Listener: l, sem: make(chan struct{}, max)}
}

// Accept blocks until a connection slot is available, then accepts.
func (ll *limitListener) Accept() (net.Conn, error) {
	ll.sem <- struct{}{}
	c, err := ll.Listener.Accept()
	if err != nil {
		<-ll.sem
		return nil, err
	}
	return &limitConn{Conn: c, release: ll.release}, nil
}

func (ll *limitListener) release() { <-ll.sem }

// limitConn wraps a net.Conn so that the listener's semaphore slot is
// released exactly once when the connection is closed, regardless of how
// many times Close is called (design decision D14: don't double-decrement
// the connection limiter on a path that might close the same conn twice,
// e.g. once explicitly and once via a deferred cleanup).
type limitConn struct {
	net.Conn
	releaseOnce sync.Once
	release     func()
}

func (lc *limitConn) Close() error {
	err := lc.Conn.Close()
	lc.releaseOnce.Do(lc.release)
	return err
}

// RecoverMiddleware wraps an http.Handler so that a panic in any handler
// results in a 500 response and a logged error, rather than crashing the
// whole server (fail-closed availability guarantee, mirrors the bucket
// package's own panic-recovery in design decision D7).
func RecoverMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if logger != nil {
					logger.Error("panic recovered in http handler", "panic", rec, "path", r.URL.Path)
				}
				w.WriteHeader(http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
