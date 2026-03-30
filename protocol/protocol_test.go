// Copyright 2009 The Ninep Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package protocol

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"reflect"
	"testing"
)

var (
	removedFID2 bool
)

func print9p(f string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, f+"\n", args...)
}

func newEcho() *echo {
	return &echo{
		qids: make(map[FID]QID),
	}
}

func TestEncode(t *testing.T) {
	var tests = []struct {
		n string
		b []byte
		f func(b *bytes.Buffer)
	}{
		{
			"TVersion test with 8192 byte msize and 9P2000",
			[]byte{19, 0, 0, 0, 100, 0x55, 0xaa, 0, 32, 0, 0, 6, 0, 57, 80, 50, 48, 48, 48},
			func(b *bytes.Buffer) { MarshalTversionPkt(b, Tag(0xaa55), 8192, "9P2000") },
		},
		{
			"RVersion test with 8192 byte msize and 9P2000",
			[]byte{19, 0, 0, 0, 101, 0xaa, 0x55, 0, 32, 0, 0, 6, 0, 57, 80, 50, 48, 48, 48},
			func(b *bytes.Buffer) { MarshalRversionPkt(b, Tag(0x55aa), 8192, "9P2000") },
		},
	}

	for _, v := range tests {
		var b bytes.Buffer
		v.f(&b)
		if !reflect.DeepEqual(v.b, b.Bytes()) {
			t.Errorf("Mismatch on %v: Got\n%v[%v], want\n%v[%v]", v.n, b.Bytes(), len(b.Bytes()), v.b, len(v.b))
		}
	}
}

func TestTags(t *testing.T) {
	c, err := NewClient()
	if err != nil {
		t.Fatalf("%v", err)
	}
	_ = c.GetTag()
	if len(c.Tags) != NumTags-1 {
		t.Errorf("Got one tag, len(tags) is %d, want %d", len(c.Tags), NumTags-1)
	}
}

type echo struct {
	qids map[FID]QID
}

func (e *echo) Rversion(msize MaxSize, version string) (MaxSize, string, error) {
	if version != "9P2000" {
		return 0, "", fmt.Errorf("%v not supported; only 9P2000", version)
	}
	return msize, version, nil
}

func (e *echo) Rattach(FID, FID, string, string) (QID, error) {
	return QID{}, nil
}

func (e *echo) Rflush(o Tag) error {
	switch o {
	case 3:
		return nil
	}
	return fmt.Errorf("Rflush: bad Tag %v", o)
}

func (e *echo) Rwalk(fid FID, newfid FID, paths []string) ([]QID, error) {
	if len(paths) > 1 {
		return nil, nil
	}
	switch paths[0] {
	case "null":
		return []QID{{Type: 0, Version: 0, Path: 0xaa55}}, nil
	}
	return nil, nil
}

func (e *echo) Ropen(fid FID, mode Mode) (QID, MaxSize, error) {
	return QID{}, 4000, nil
}
func (e *echo) Rcreate(fid FID, name string, perm Perm, mode Mode) (QID, MaxSize, error) {
	return QID{}, 5000, nil
}
func (e *echo) Rclunk(f FID) error {
	switch int(f) {
	case 2:
		if removedFID2 {
			return fmt.Errorf("Clunk: bad FID %v", f)
		}
		return nil
	}
	return fmt.Errorf("Clunk: bad FID %v", f)
}
func (e *echo) Rstat(f FID) ([]byte, error) {
	switch int(f) {
	case 2:
		return []byte{}, nil
	}
	return []byte{}, fmt.Errorf("Stat: bad FID %v", f)
}
func (e *echo) Rwstat(f FID, s []byte) error {
	switch int(f) {
	case 2:
		return nil
	}
	return fmt.Errorf("Wstat: bad FID %v", f)
}
func (e *echo) Rremove(f FID) error {
	switch int(f) {
	case 2:
		removedFID2 = true
		return nil
	}
	return fmt.Errorf("Remove: bad FID %v", f)
}
func (e *echo) Rread(f FID, o Offset, c Count) ([]byte, error) {
	switch int(f) {
	case 2:
		return []byte("HI"), nil
	}
	return nil, fmt.Errorf("Read: bad FID %v", f)
}

func (e *echo) Rwrite(f FID, o Offset, b []byte) (Count, error) {
	switch int(f) {
	case 2:
		return Count(len(b)), nil
	}
	return -1, fmt.Errorf("Write: bad FID %v", f)
}

func TestTManyRPCs(t *testing.T) {
	p, p2 := net.Pipe()

	c, err := NewClient(func(c *Client) error {
		c.FromNet, c.ToNet = p, p
		return nil
	},
		func(c *Client) error {
			c.Msize = 8192
			c.Trace = print9p
			return nil
		})
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("Client is %v", c.String())

	e := newEcho()
	s, err := NewServer(e, func(s *Server) error {
		s.Trace = print9p
		return nil
	})
	if err != nil {
		t.Fatalf("NewServer: want nil, got %v", err)
	}

	if err := s.Accept(p2); err != nil {
		t.Fatalf("Accept: want nil, got %v", err)
	}

	for i := 0; i < 256*1024; i++ {
		_, _, err := c.CallTversion(8000, "9P2000")
		if err != nil {
			t.Fatalf("CallTversion: want nil, got %v", err)
		}
	}
}

func TestTMessages(t *testing.T) {
	removedFID2 = false
	p, p2 := net.Pipe()

	c, err := NewClient(func(c *Client) error {
		c.FromNet, c.ToNet = p, p
		return nil
	},
		func(c *Client) error {
			c.Msize = 8192
			c.Trace = print9p
			return nil
		})
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("Client is %v", c.String())

	e := newEcho()
	s, err := NewServer(e, func(s *Server) error {
		s.Trace = print9p
		s.NS = e
		return nil
	})

	if err != nil {
		t.Fatalf("NewServer: want nil, got %v", err)
	}

	if err := s.Accept(p2); err != nil {
		t.Fatalf("Accept: want nil, got %v", err)
	}

	m, v, err := c.CallTversion(8000, "9p3000")
	if err == nil {
		t.Fatalf("CallTversion: want err, got nil")
	}
	t.Logf("CallTversion: wanted an error and got %v", err)

	m, v, err = c.CallTversion(8000, "9P2000")
	if err != nil {
		t.Fatalf("CallTversion: want nil, got %v", err)
	}
	t.Logf("CallTversion: msize %v version %v", m, v)

	t.Logf("Server is %v", s.String())
	a, err := c.CallTattach(0, 0, "", "")
	if err != nil {
		t.Fatalf("CallTattach: want nil, got %v", err)
	}
	t.Logf("Attach is %v", a)
	w, err := c.CallTwalk(0, 1, []string{"hi", "there"})
	if err != nil {
		t.Fatalf("CallTwalk(0,1,[\"hi\", \"there\"]): want nil, got %v", err)
	}
	if len(w) != 0 {
		t.Fatalf("CallTwalk(0,1,[\"hi\", \"there\"]): want 0 QIDS, got  back %d", len(w))
	}
	t.Logf("Walk is %v", w)

	w, err = c.CallTwalk(0, 1, []string{"null"})
	if err != nil {
		t.Errorf("CallTwalk(0,1,\"null\"): want nil, got err %v", err)
	}
	if len(w) != 1 {
		t.Errorf("CallTwalk(0,1,\"null\"): want 1 QIDs, got back %d", len(w))
	}
	t.Logf("Walk is %v", w)

	q, iounit, err := c.CallTopen(1, 1)
	if err != nil {
		t.Fatalf("CallTopen: want nil, got %v", err)
	}
	t.Logf("Open is %v %v", q, iounit)

	d, err := c.CallTread(FID(2), 0, 5)
	if err != nil {
		t.Fatalf("CallTread: want nil, got %v", err)
	}
	t.Logf("Read is %v", d)

	_, err = c.CallTwrite(FID(2), 0, d)
	if err != nil {
		t.Fatalf("CallTwrite: want nil, got %v", err)
	}

	if err := c.CallTclunk(FID(2)); err != nil {
		t.Fatalf("CallTclunk: want nil, got %v", err)
	}
	if err := c.CallTremove(FID(1)); err == nil {
		t.Fatalf("CallTremove: want err, got nil")
	}
	if err := c.CallTremove(FID(2)); err != nil {
		t.Fatalf("CallTremove: want nil, got %v", err)
	}
	if err := c.CallTclunk(FID(2)); err == nil {
		t.Fatalf("Callclunk on removed file: want err, got nil")
	}
	if err := c.CallTremove(FID(1)); err == nil {
		t.Fatalf("CallTremove: want err, got nil")
	}
	st, err := c.CallTstat(FID(2))
	if err != nil {
		t.Fatalf("CallTstat: want nil, got %v", err)
	}
	t.Logf("Stat: Got %v", st)

	if _, err := c.CallTstat(FID(1)); err == nil {
		t.Fatalf("CallTstat: want err, got nil")
	}
	if err := c.CallTwstat(FID(2), []byte{}); err != nil {
		t.Fatalf("CallTwstat: want nil, got %v", err)
	}

	if err := c.CallTwstat(FID(1), []byte{}); err == nil {
		t.Fatalf("CallTwstat: want err, got nil")
	}
	if err := c.CallTflush(3); err != nil {
		t.Fatalf("CallTflush: want nil, got %v", err)
	}

	if err := c.CallTflush(2); err == nil {
		t.Fatalf("CallTflush: want err, got nil")
	}
}

func BenchmarkNull(b *testing.B) {
	p, p2 := net.Pipe()

	c, err := NewClient(func(c *Client) error {
		c.FromNet, c.ToNet = p, p
		return nil
	},
		func(c *Client) error {
			c.Msize = 8192
			return nil
		})
	if err != nil {
		b.Fatalf("%v", err)
	}
	b.Logf("Client is %v", c.String())

	e := newEcho()
	s, err := NewServer(e, func(s *Server) error {
		s.NS = e
		return nil
	})

	if err != nil {
		b.Fatalf("NewServer: want nil, got %v", err)
	}

	if err := s.Accept(p2); err != nil {
		b.Fatalf("Accept: want nil, got %v", err)
	}

	b.Logf("%d iterations", b.N)
	for i := 0; i < b.N; i++ {
		if _, err := c.CallTread(FID(2), 0, 5); err != nil {
			b.Fatalf("CallTread: want nil, got %v", err)
		}
	}
}
