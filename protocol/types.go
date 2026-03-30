// Copyright 2009 The Ninep Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package protocol

// File is a placeholder for future file-related state. It is identified by a QID on the wire.
type File struct {
}

// Service is a function type that accepts a work function and a FID abort channel.
// It executes the work function and handles FID-related aborts.
type Service func(func() error, chan FID)

// FileServer maintains file system server state.
type FileServer struct {
	Server
	Versioned bool
}
