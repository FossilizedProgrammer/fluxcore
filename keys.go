package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// ---- WireGuard keypair -----------------------------------------------------

func clampScalar(k []byte) {
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
}

// generateKeypair makes a fresh WireGuard-compatible X25519 keypair.
func generateKeypair() (Keypair, error) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		return Keypair{}, err
	}
	clampScalar(priv)
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return Keypair{}, err
	}
	return Keypair{
		PrivateKey: base64.StdEncoding.EncodeToString(priv),
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
	}, nil
}

// publicKeyFromPrivate derives the base64 public key for a base64 private key.
func publicKeyFromPrivate(privateB64 string) (string, error) {
	priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privateB64))
	if err != nil || len(priv) != 32 {
		return "", errors.New("private key must be base64 of exactly 32 bytes")
	}
	clampScalar(priv)
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

func keypairFromPrivate(privateB64 string) (Keypair, error) {
	pub, err := publicKeyFromPrivate(privateB64)
	if err != nil {
		return Keypair{}, err
	}
	return Keypair{PrivateKey: privateB64, PublicKey: pub}, nil
}

func privateKeyHex(privateB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privateB64))
	if err != nil || len(raw) != 32 {
		return "", errors.New("private key must be base64 of exactly 32 bytes")
	}
	return fmt.Sprintf("%x", raw), nil
}

func publicKeyHex(pubB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubB64))
	if err != nil || len(raw) != 32 {
		return "", errors.New("public key must be base64 of exactly 32 bytes")
	}
	return fmt.Sprintf("%x", raw), nil
}

// ---- base58 ----------------------------------------------------------------

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Encode(input []byte) string {
	zeros := 0
	for zeros < len(input) && input[zeros] == 0 {
		zeros++
	}
	num := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)
	var out []byte
	for num.Cmp(zero) > 0 {
		num.DivMod(num, base, mod)
		out = append(out, base58Alphabet[mod.Int64()])
	}
	for i := 0; i < zeros; i++ {
		out = append(out, '1')
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func base58Decode(s string) ([]byte, error) {
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}
	num := big.NewInt(0)
	base := big.NewInt(58)
	for _, c := range s {
		idx := strings.IndexRune(base58Alphabet, c)
		if idx < 0 {
			return nil, fmt.Errorf("invalid base58 character %q", c)
		}
		num.Mul(num, base)
		num.Add(num, big.NewInt(int64(idx)))
	}
	body := num.Bytes()
	out := make([]byte, zeros+len(body))
	copy(out[zeros:], body)
	return out, nil
}

// ---- recovery key ----------------------------------------------------------

const (
	recoveryPrefix  = "CVPN"
	recoveryVersion = 1
)

var errInvalidRecoveryKey = errors.New("invalid recovery key")

// encodeRecoveryKey: CVPN- + base58(version ‖ key ‖ sha256(version‖key)[0:4]),
// grouped by five characters.
func encodeRecoveryKey(privateB64 string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privateB64))
	if err != nil || len(key) != 32 {
		return "", errors.New("encodeRecoveryKey: expected a 32-byte key")
	}
	payload := append([]byte{recoveryVersion}, key...)
	sum := sha256.Sum256(payload)
	body := append(payload, sum[:4]...)
	encoded := base58Encode(body)
	var groups []string
	for i := 0; i < len(encoded); i += 5 {
		end := i + 5
		if end > len(encoded) {
			end = len(encoded)
		}
		groups = append(groups, encoded[i:end])
	}
	return strings.Join(append([]string{recoveryPrefix}, groups...), "-"), nil
}

// decodeRecoveryKey is forgiving about presentation and strict about content.
func decodeRecoveryKey(input string) (Keypair, error) {
	s := strings.Join(strings.Fields(input), "")
	if len(s) >= len(recoveryPrefix) && strings.EqualFold(s[:len(recoveryPrefix)], recoveryPrefix) {
		s = s[len(recoveryPrefix):]
	}
	s = strings.ReplaceAll(s, "-", "")
	body, err := base58Decode(s)
	if err != nil || len(body) != 1+32+4 {
		return Keypair{}, errInvalidRecoveryKey
	}
	payload := body[:33]
	sum := sha256.Sum256(payload)
	for i := 0; i < 4; i++ {
		if sum[i] != body[33+i] {
			return Keypair{}, fmt.Errorf("%w (checksum)", errInvalidRecoveryKey)
		}
	}
	if payload[0] != recoveryVersion {
		return Keypair{}, fmt.Errorf("%w (version)", errInvalidRecoveryKey)
	}
	return keypairFromPrivate(base64.StdEncoding.EncodeToString(payload[1:]))
}

// ---- proof of work ---------------------------------------------------------

func hasLeadingZeroBits(digest []byte, bits int) bool {
	full := bits / 8
	for i := 0; i < full; i++ {
		if digest[i] != 0 {
			return false
		}
	}
	if rem := bits % 8; rem != 0 {
		mask := byte(0xff << (8 - rem))
		if digest[full]&mask != 0 {
			return false
		}
	}
	return true
}

func powDigest(publicKeyB64, nonce string) [32]byte {
	h := sha256.New()
	h.Write([]byte(publicKeyB64))
	h.Write([]byte(nonce))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// solvePoW starts from a random offset so re-enrolling the same key yields a
// different nonce (the gateway single-uses each pair).
func solvePoW(publicKeyB64 string, bits int) string {
	startBig, err := rand.Int(rand.Reader, big.NewInt(1<<30))
	start := int64(0)
	if err == nil {
		start = startBig.Int64()
	}
	for i := start; ; i++ {
		nonce := fmt.Sprintf("%d", i)
		d := powDigest(publicKeyB64, nonce)
		if hasLeadingZeroBits(d[:], bits) {
			return nonce
		}
	}
}

func verifyPoW(publicKeyB64, nonce string, bits int) bool {
	if nonce == "" {
		return false
	}
	d := powDigest(publicKeyB64, nonce)
	return hasLeadingZeroBits(d[:], bits)
}
