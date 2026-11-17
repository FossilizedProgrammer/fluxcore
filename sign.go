package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// apiError is a gateway error envelope.
type apiError struct {
	Code    string
	Slug    string
	Message string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("gateway error %s (%s): %s", e.Code, e.Slug, e.Message)
}

// signedResult is a verified control-API response.
type signedResult struct {
	Data       []byte
	SignPubKey string
}

var httpClient = &http.Client{}

// fetchSigned fetches a signed control-API endpoint and verifies the Ed25519
// signature over the exact response bytes. Error bodies are not signed.
func fetchSigned(ctx context.Context, url, method string, body []byte, pinnedSignPubKey string, timeout time.Duration) (*signedResult, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return nil, err
	}

	var envelope struct {
		Status string          `json:"status"`
		Data   json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("%s: invalid API response: %w", url, err)
	}
	if envelope.Status == "error" {
		var detail ApiErrorDetail
		_ = json.Unmarshal(envelope.Data, &detail)
		return nil, &apiError{Code: detail.Code, Slug: detail.Name, Message: detail.Message}
	}
	if envelope.Status != "success" {
		return nil, fmt.Errorf("%s: unexpected envelope status %q", url, envelope.Status)
	}

	headerPub := res.Header.Get("X-CVPN-Sign-PubKey")
	signature := res.Header.Get("X-CVPN-Signature")
	signPubKey := pinnedSignPubKey
	if signPubKey == "" {
		signPubKey = headerPub
	}
	if signature == "" || signPubKey == "" {
		return nil, fmt.Errorf("fetchSigned: unsigned response from %s", url)
	}
	if !verifySignedResponse(raw, signature, signPubKey) {
		return nil, fmt.Errorf("fetchSigned: unverified signed response from %s", url)
	}
	return &signedResult{Data: envelope.Data, SignPubKey: signPubKey}, nil
}

func verifySignedResponse(body []byte, signatureB64, publicKeyB64 string) bool {
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	pub, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pub, body, sig)
}

// ---- canonical JSON (for the signed directory) -----------------------------

// canonicalJSON serializes with recursively sorted object keys and no
// insignificant whitespace, matching the signer's pragmatic canonicalizer.
func canonicalJSON(value any) (string, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, value); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func writeCanonical(buf *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		buf.Write(b)
	case json.Number:
		buf.WriteString(v.String())
	case float64:
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		buf.Write(b)
	case []any:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			buf.Write(kb)
			buf.WriteByte(':')
			if err := writeCanonical(buf, v[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		buf.Write(b)
	}
	return nil
}

// directoryVerify verifies a signed directory against the pinned key. The
// signature covers every field except sig, sign_pubkey and // comment keys.
func directoryVerify(dir Directory, publicKeyB64 string) bool {
	raw, err := json.Marshal(dir)
	if err != nil {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return false
	}
	delete(doc, "sig")
	delete(doc, "sign_pubkey")
	for k := range doc {
		if strings.HasPrefix(k, "//") {
			delete(doc, k)
		}
	}
	message, err := canonicalJSON(doc)
	if err != nil {
		return false
	}
	return verifySignedResponse([]byte(message), dir.Sig, publicKeyB64)
}

// ---- directory snapshot ----------------------------------------------------

// Pinned directory Ed25519 public key (CVPN_DIRECTORY_PUBKEY).
const directoryPublicKey = "1e+42nEpmdjf/cAHs+yE2E2iwmAADpWiLy1VMepsKKw="

var errDirectoryInvalid = errors.New("bundled directory failed signature verification")
