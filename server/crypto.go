package server

import (
	"fmt"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"gopkg.in/square/go-jose.v2"
)

// JWESessionCodec wraps a standard SessionCodec and applies JWE encryption
// to the session token, following the "sign-then-encrypt" pattern.
type JWESessionCodec struct {
	wrapped samlsp.SessionCodec
}

func (c JWESessionCodec) New(assertion *saml.Assertion) (samlsp.Session, error) {
	return c.wrapped.New(assertion)
}

// Encode first creates a signed JWT (JWS) using the wrapped codec, and then
// encrypts the entire JWS payload using JWE.
func (c JWESessionCodec) Encode(s samlsp.Session) (string, error) {
	// 1. Get the signed JWT (JWS) from the underlying codec.
	signed, err := c.wrapped.Encode(s)
	if err != nil {
		return "", fmt.Errorf("failed to encode and sign inner session: %w", err)
	}

	// 2. Get the public key from the underlying codec to use for encryption.
	codec, ok := c.wrapped.(samlsp.JWTSessionCodec)
	if !ok {
		return "", fmt.Errorf("wrapped session codec is not a JWTSessionCodec")
	}
	publicKey := &codec.Key.PublicKey

	// 3. Create a JWE encrypter.
	encrypter, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.RSA_OAEP, Key: publicKey}, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create jwe encrypter: %w", err)
	}

	// 4. Encrypt the signed token.
	jwe, err := encrypter.Encrypt([]byte(signed))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt jws payload: %w", err)
	}

	return jwe.CompactSerialize()
}

// Decode first decrypts the JWE payload to get the signed JWT (JWS), and then
// uses the wrapped codec to decode and validate the JWS.
func (c JWESessionCodec) Decode(encrypted string) (samlsp.Session, error) {
	// 1. Parse the JWE token.
	jwe, err := jose.ParseEncrypted(encrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to parse jwe token: %w", err)
	}

	// 2. Get the private key from the underlying codec to use for decryption.
	codec, ok := c.wrapped.(samlsp.JWTSessionCodec)
	if !ok {
		return nil, fmt.Errorf("wrapped session codec is not a JWTSessionCodec")
	}
	privateKey := codec.Key

	// 3. Decrypt the JWE to get the JWS.
	decrypted, err := jwe.Decrypt(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt jwe token: %w", err)
	}

	// 4. Decode the inner JWS using the wrapped codec.
	return c.wrapped.Decode(string(decrypted))
}