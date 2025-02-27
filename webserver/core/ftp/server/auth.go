// Copyright 2018 The goftp Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package server

import (
	"crypto/subtle"
)

// Auth is an interface to auth your ftp user login.
type Auth interface {
	CheckPasswd(string, string) (bool, error)
}

var (
	_ Auth = &SimpleAuth{}
	_ Auth = &NoAuth{}
)

// SimpleAuth implements Auth interface to provide a memory user login auth
type SimpleAuth struct {
	Name     string
	Password string
}

type NoAuth struct{}

// CheckPasswd will check user's password
func (a *SimpleAuth) CheckPasswd(name, pass string) (bool, error) {
	return constantTimeEquals(name, a.Name) && constantTimeEquals(pass, a.Password), nil
}

func (a *NoAuth) CheckPasswd(name, pass string) (bool, error) {
	return true, nil
}

func constantTimeEquals(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
