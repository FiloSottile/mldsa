// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package x509 implements PKIX public key and PKCS #8 private key parsing and
// marshaling for ML-DSA keys.
//
// For all non-ML-DSA key types, it dispatches to the standard library's
// crypto/x509 package.
package x509

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"filippo.io/mldsa"
)

// OIDs from RFC 9881, Section 2.
var (
	oidPublicKeyMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidPublicKeyMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidPublicKeyMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
)

// pkixPublicKey reflects a PKIX public key structure. See SubjectPublicKeyInfo
// in RFC 5280, Section 4.1.
type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

// pkcs8 reflects an ASN.1, PKCS #8 PrivateKey. See RFC 5208.
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

func isMLDSAOID(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(oidPublicKeyMLDSA44) ||
		oid.Equal(oidPublicKeyMLDSA65) ||
		oid.Equal(oidPublicKeyMLDSA87)
}

func mldsaParametersFromOID(oid asn1.ObjectIdentifier) (mldsa.Parameters, bool) {
	switch {
	case oid.Equal(oidPublicKeyMLDSA44):
		return mldsa.MLDSA44(), true
	case oid.Equal(oidPublicKeyMLDSA65):
		return mldsa.MLDSA65(), true
	case oid.Equal(oidPublicKeyMLDSA87):
		return mldsa.MLDSA87(), true
	}
	return mldsa.Parameters{}, false
}

func oidFromMLDSAParameters(params mldsa.Parameters) (asn1.ObjectIdentifier, bool) {
	switch params {
	case mldsa.MLDSA44():
		return oidPublicKeyMLDSA44, true
	case mldsa.MLDSA65():
		return oidPublicKeyMLDSA65, true
	case mldsa.MLDSA87():
		return oidPublicKeyMLDSA87, true
	}
	return nil, false
}

// ParsePKIXPublicKey parses a public key in PKIX, ASN.1 DER form. The encoded
// public key is a SubjectPublicKeyInfo structure (see RFC 5280, Section 4.1).
//
// It returns a *[mldsa.PublicKey] for ML-DSA keys, and otherwise returns the
// same key types as [crypto/x509.ParsePKIXPublicKey].
func ParsePKIXPublicKey(derBytes []byte) (pub any, err error) {
	var pki pkixPublicKey
	if rest, err := asn1.Unmarshal(derBytes, &pki); err != nil {
		return x509.ParsePKIXPublicKey(derBytes)
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of public-key")
	}

	if !isMLDSAOID(pki.Algo.Algorithm) {
		return x509.ParsePKIXPublicKey(derBytes)
	}

	if len(pki.Algo.Parameters.FullBytes) != 0 {
		return nil, errors.New("x509: ML-DSA key encoded with illegal parameters")
	}
	params, ok := mldsaParametersFromOID(pki.Algo.Algorithm)
	if !ok {
		return nil, errors.New("x509: unsupported ML-DSA parameters")
	}
	return mldsa.NewPublicKey(params, pki.BitString.RightAlign())
}

// MarshalPKIXPublicKey converts a public key to PKIX, ASN.1 DER form. The
// encoded public key is a SubjectPublicKeyInfo structure (see RFC 5280,
// Section 4.1).
//
// It supports *[mldsa.PublicKey] values directly, and otherwise dispatches to
// [crypto/x509.MarshalPKIXPublicKey].
func MarshalPKIXPublicKey(pub any) ([]byte, error) {
	pk, ok := pub.(*mldsa.PublicKey)
	if !ok {
		return x509.MarshalPKIXPublicKey(pub)
	}

	oid, ok := oidFromMLDSAParameters(pk.Parameters())
	if !ok {
		return nil, errors.New("x509: unsupported ML-DSA parameters")
	}
	pki := pkixPublicKey{
		Algo: pkix.AlgorithmIdentifier{Algorithm: oid},
		BitString: asn1.BitString{
			Bytes:     pk.Bytes(),
			BitLength: 8 * len(pk.Bytes()),
		},
	}
	return asn1.Marshal(pki)
}

// ParsePKCS8PrivateKey parses an unencrypted private key in PKCS #8, ASN.1 DER
// form.
//
// It returns a *[mldsa.PrivateKey] for ML-DSA keys, and otherwise returns the
// same key types as [crypto/x509.ParsePKCS8PrivateKey].
//
// Before Go 1.24, the CRT parameters of RSA keys were ignored and recomputed.
// To restore the old behavior, use the GODEBUG=x509rsacrt=0 environment
// variable.
func ParsePKCS8PrivateKey(der []byte) (key any, err error) {
	var privKey pkcs8
	if rest, err := asn1.Unmarshal(der, &privKey); err != nil {
		return x509.ParsePKCS8PrivateKey(der)
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of private-key")
	}

	if !isMLDSAOID(privKey.Algo.Algorithm) {
		return x509.ParsePKCS8PrivateKey(der)
	}

	if l := len(privKey.Algo.Parameters.FullBytes); l != 0 {
		return nil, errors.New("x509: invalid ML-DSA private key parameters")
	}
	if l := len(privKey.PrivateKey); l == 0 {
		return nil, fmt.Errorf("x509: invalid ML-DSA private key length: %d", l)
	}
	switch privKey.PrivateKey[0] {
	case 0x80: // IMPLICIT [0] OCTET STRING (seed)
	case 0x04: // OCTET STRING (expandedKey)
		return nil, errors.New("x509: semi-expanded ML-DSA private keys without seed are not supported")
	case 0x30: // SEQUENCE (both)
		return nil, errors.New(`x509: ML-DSA private keys with both seed and expanded key are not supported, use e.g. "openssl pkey -provparam ml-dsa.output_formats=seed-only" to convert to a seed-only key`)
	default:
		return nil, fmt.Errorf("x509: invalid ML-DSA private key: invalid ASN.1 tag %02x", privKey.PrivateKey[0])
	}
	if l := len(privKey.PrivateKey); l != 2+mldsa.PrivateKeySize {
		return nil, fmt.Errorf("x509: invalid ML-DSA private key length: %d", l)
	}
	if privKey.PrivateKey[1] != mldsa.PrivateKeySize {
		return nil, errors.New("x509: invalid ML-DSA private key ASN.1 encoding")
	}
	params, ok := mldsaParametersFromOID(privKey.Algo.Algorithm)
	if !ok {
		return nil, errors.New("x509: unknown ML-DSA parameters")
	}
	return mldsa.NewPrivateKey(params, privKey.PrivateKey[2:])
}

// MarshalPKCS8PrivateKey converts a private key to PKCS #8, ASN.1 DER form.
//
// It supports *[mldsa.PrivateKey] values directly, and otherwise dispatches to
// [crypto/x509.MarshalPKCS8PrivateKey].
//
// MarshalPKCS8PrivateKey runs rsa.PrivateKey.Precompute on RSA keys.
func MarshalPKCS8PrivateKey(key any) ([]byte, error) {
	sk, ok := key.(*mldsa.PrivateKey)
	if !ok {
		return x509.MarshalPKCS8PrivateKey(key)
	}

	oid, ok := oidFromMLDSAParameters(sk.PublicKey().Parameters())
	if !ok {
		return nil, errors.New("x509: unknown ML-DSA parameters while marshaling to PKCS#8")
	}
	privKey := pkcs8{
		Algo:       pkix.AlgorithmIdentifier{Algorithm: oid},
		PrivateKey: append([]byte{0x80, mldsa.PrivateKeySize}, sk.Bytes()...),
	}
	return asn1.Marshal(privKey)
}
