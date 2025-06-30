package server

import (
	"crypto/rsa"
	"fmt"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/go-jose/go-jose/v4"
)

// JWESessionCodec wraps a JWTSessionCodec and applies JWE encryption to protect sensitive attributes
type JWESessionCodec struct {
	jwtSessionCodec *samlsp.JWTSessionCodec
	encrypter       jose.Encrypter
	privateKey      *rsa.PrivateKey
}

func NewJWESessionCodec(codec *samlsp.JWTSessionCodec) (samlsp.SessionCodec, error) {
	// get the public and private key from the underlying codec to use for encryption
	publicKey := &codec.Key.PublicKey
	privateKey := codec.Key

	// create a JWE encrypter (possible to parameterize jose.ContentEncryption and jose.KeyAlgorithm)
	encrypter, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.RSA_OAEP, Key: publicKey}, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create jwe encrypter: %w", err)
	}

	return &JWESessionCodec{jwtSessionCodec: codec, encrypter: encrypter, privateKey: privateKey}, nil
}

func (c *JWESessionCodec) New(assertion *saml.Assertion) (samlsp.Session, error) {
	return c.jwtSessionCodec.New(assertion)
}

// Encode first creates a signed JWT (JWS) using the wrapped codec, and then encrypts the entire JWS payload using JWE.
func (c *JWESessionCodec) Encode(s samlsp.Session) (string, error) {
	// get the signed JWT (JWS) from the underlying codec
	signed, err := c.jwtSessionCodec.Encode(s)
	if err != nil {
		return "", fmt.Errorf("failed to encode and sign inner session: %w", err)
	}

	// encrypt the signed token with JWE
	jwe, err := c.encrypter.Encrypt([]byte(signed))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt jws payload: %w", err)
	}

	return jwe.CompactSerialize()
}

// Decode first decrypts the JWE payload to get the signed JWT (JWS), and then uses the wrapped codec to decode and
// validate the JWS
func (c *JWESessionCodec) Decode(encrypted string) (samlsp.Session, error) {
	// parse the JWE token (possible to parameterize jose.ContentEncryption and jose.KeyAlgorithm)
	jwe, err := jose.ParseEncrypted(encrypted, []jose.KeyAlgorithm{jose.RSA_OAEP}, []jose.ContentEncryption{jose.A128GCM})
	if err != nil {
		return nil, fmt.Errorf("failed to parse jwe token: %w", err)
	}

	// decrypt the JWE to get the JWS
	decrypted, err := jwe.Decrypt(c.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt jwe token: %w", err)
	}

	// decode the inner JWS using the wrapped codec
	return c.jwtSessionCodec.Decode(string(decrypted))
}
