// Copyright 2009 The Ninep Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package protocol

// A File is defined by a QID. File Servers never see a FID.
type File struct {
}

// A service is a closure which returns an error or nil.
type Service func(func() error, chan FID)

// FileServer maintains file system server state.
type FileServer struct {
	Server
	Versioned bool
}
