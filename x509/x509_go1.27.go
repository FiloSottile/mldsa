// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.27 && !fips140v1.0

// Package x509 is a transparent wrapper around the standard library's
// crypto/x509 package.
package x509

import "crypto/x509"

// ParsePKIXPublicKey calls [x509.ParsePKIXPublicKey].
func ParsePKIXPublicKey(derBytes []byte) (pub any, err error) {
	return x509.ParsePKIXPublicKey(derBytes)
}

// MarshalPKIXPublicKey calls [x509.MarshalPKIXPublicKey].
func MarshalPKIXPublicKey(pub any) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pub)
}

// ParsePKCS8PrivateKey calls [x509.ParsePKCS8PrivateKey].
func ParsePKCS8PrivateKey(der []byte) (key any, err error) {
	return x509.ParsePKCS8PrivateKey(der)
}

// MarshalPKCS8PrivateKey calls [x509.MarshalPKCS8PrivateKey].
func MarshalPKCS8PrivateKey(key any) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(key)
}
