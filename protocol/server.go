// Copyright 2012 The Ninep Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const DefaultAddr = ":5640"

type NsCreator func() NineServer

type Listener struct {
	nsCreator NsCreator

	// TCP address to listen on, default is DefaultAddr
	Addr string

	// Trace function for logging
	Trace Tracer

	// mu guards below
	mu sync.Mutex

	listeners map[net.Listener]struct{}
}

// Server is a 9p server.
type Server struct {
	NS    NineServer
	D     Dispatcher
	Trace Tracer
}

type conn struct {
	listener *Listener

	// server on which the connection arrived.
	server *Server

	// rwc is the underlying network connection.
	rwc net.Conn

	// remoteAddr is rwc.RemoteAddr().String().
	remoteAddr string

	// replies
	replies chan RPCReply

	// dead is set to true when we finish reading packets.
	dead bool
}

func NewListener(nsCreator NsCreator, opts ...ListenerOpt) (*Listener, error) {
	l := &Listener{
		nsCreator: nsCreator,
	}

	for _, o := range opts {
		if err := o(l); err != nil {
			return nil, err
		}
	}

	return l, nil
}

func (l *Listener) newConn(rwc net.Conn) (*conn, error) {
	ns := l.nsCreator()
	server := &Server{NS: ns, D: Dispatch}

	c := &conn{
		server:   server,
		listener: l,
		rwc:      rwc,
		replies:  make(chan RPCReply, NumTags),
	}

	return c, nil
}

// trackListener tracks active listeners.
func (l *Listener) trackListener(ln net.Listener, add bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.listeners == nil {
		l.listeners = make(map[net.Listener]struct{})
	}

	if add {
		l.listeners[ln] = struct{}{}
	} else {
		delete(l.listeners, ln)
	}
}

// closeListenersLocked closes all tracked listeners.
func (l *Listener) closeListenersLocked() error {
	var err error
	for ln := range l.listeners {
		if cerr := ln.Close(); cerr != nil && err == nil {
			err = cerr
		}
		delete(l.listeners, ln)
	}
	return err
}

// Serve accepts incoming connections on the Listener. It blocks until an
// error occurs and closes the listener before returning.
func (l *Listener) Serve(ln net.Listener) error {
	defer ln.Close()

	var tempDelay time.Duration

	l.trackListener(ln, true)
	defer l.trackListener(ln, false)

	for {
		conn, err := ln.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				l.logf("9p: Accept error: %v; retrying in %v", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return err
		}
		tempDelay = 0

		if err := l.Accept(conn); err != nil {
			return err
		}
	}
}

// Accept a new connection.
func (l *Listener) Accept(conn net.Conn) error {
	c, err := l.newConn(conn)
	if err != nil {
		return err
	}

	go c.serve()
	return nil
}

// Shutdown closes all active listeners.
func (l *Listener) Shutdown() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.closeListenersLocked()
}

func (l *Listener) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return fmt.Sprintf("Listener addr=%v activeListeners=%d", l.Addr, len(l.listeners))
}

func (l *Listener) logf(format string, args ...interface{}) {
	if l.Trace != nil {
		l.Trace(format, args...)
	}
}

func (c *conn) String() string {
	return fmt.Sprintf("Dead %v %d replies pending", c.dead, len(c.replies))
}

func (c *conn) logf(format string, args ...interface{}) {
	c.listener.logf("[%v] "+format, append([]interface{}{c.remoteAddr}, args...)...)
}

func (c *conn) serve() {
	if c.rwc == nil {
		c.dead = true
		return
	}

	c.remoteAddr = c.rwc.RemoteAddr().String()

	defer c.rwc.Close()

	c.logf("Starting readNetPackets")

	for !c.dead {
		l := make([]byte, 7)
		if n, err := c.rwc.Read(l); err != nil || n < 7 {
			c.logf("readNetPackets: short read: %v", err)
			c.dead = true
			return
		}
		sz := int64(l[0]) + int64(l[1])<<8 + int64(l[2])<<16 + int64(l[3])<<24
		t := MType(l[4])
		b := bytes.NewBuffer(l[5:])
		r := io.LimitReader(c.rwc, sz-7)
		if _, err := io.Copy(b, r); err != nil {
			c.logf("readNetPackets: short read: %v", err)
			c.dead = true
			return
		}
		c.logf("readNetPackets: got %v, len %d, sending to IO", RPCNames[MType(l[4])], b.Len())
		if err := c.server.D(c.server, b, t); err != nil {
			c.logf("%v: %v", RPCNames[MType(l[4])], err)
		}
		c.logf("readNetPackets: Write %v back", b)
		amt, err := c.rwc.Write(b.Bytes())
		if err != nil {
			c.logf("readNetPackets: write error: %v", err)
			c.dead = true
			return
		}
		c.logf("Returned %v amt %v", b, amt)
	}
}

// NewServer creates a new 9p server for testing purposes (using net.Pipe).
func NewServer(ns NineServer, opts ...func(*Server) error) (*Server, error) {
	s := &Server{
		NS: ns,
		D:  Dispatch,
	}
	for _, o := range opts {
		if err := o(s); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Accept starts serving on the given connection (used for testing with net.Pipe).
func (s *Server) Accept(conn net.Conn) error {
	go func() {
		defer conn.Close()
		for {
			l := make([]byte, 7)
			if n, err := conn.Read(l); err != nil || n < 7 {
				return
			}
			sz := int64(l[0]) + int64(l[1])<<8 + int64(l[2])<<16 + int64(l[3])<<24
			t := MType(l[4])
			b := bytes.NewBuffer(l[5:])
			r := io.LimitReader(conn, sz-7)
			if _, err := io.Copy(b, r); err != nil {
				return
			}
			if s.Trace != nil {
				s.Trace("Accept: got %v, len %d", RPCNames[MType(l[4])], b.Len())
			}
			if err := s.D(s, b, t); err != nil {
				if s.Trace != nil {
					s.Trace("%v: %v", RPCNames[MType(l[4])], err)
				}
			}
			if _, err := conn.Write(b.Bytes()); err != nil {
				return
			}
		}
	}()
	return nil
}

// String returns a string representation of the server.
func (s *Server) String() string {
	return fmt.Sprintf("Server NS %v", s.NS)
}

// Dispatch dispatches a 9p request to the appropriate handler.
func Dispatch(s *Server, b *bytes.Buffer, t MType) error {
	switch t {
	case Tversion:
		return s.SrvRversion(b)
	case Tattach:
		return s.SrvRattach(b)
	case Tflush:
		return s.SrvRflush(b)
	case Twalk:
		return s.SrvRwalk(b)
	case Topen:
		return s.SrvRopen(b)
	case Tcreate:
		return s.SrvRcreate(b)
	case Tclunk:
		return s.SrvRclunk(b)
	case Tstat:
		return s.SrvRstat(b)
	case Twstat:
		return s.SrvRwstat(b)
	case Tremove:
		return s.SrvRremove(b)
	case Tread:
		return s.SrvRread(b)
	case Twrite:
		return s.SrvRwrite(b)
	}
	ServerError(b, fmt.Sprintf("Dispatch: %v not supported", RPCNames[t]))
	return nil
}
