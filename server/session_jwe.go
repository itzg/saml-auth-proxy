package server

import (
	"crypto"
	"crypto/ecdsa"
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
	privateKey      crypto.PrivateKey
	keyAlgorithm    jose.KeyAlgorithm
}

func NewJWESessionCodec(sessionCodec samlsp.SessionCodec, publicKey crypto.PublicKey, privateKey crypto.PrivateKey) (samlsp.SessionCodec, error) {
	codec, ok := sessionCodec.(samlsp.JWTSessionCodec)
	if !ok {
		return nil, fmt.Errorf("session codec isn't JWT session codec")
	}

	keyAlgorithm, err := jweKeyAlgorithmForPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	// create a JWE encrypter (possible to parameterize jose.ContentEncryption and jose.KeyAlgorithm)
	encrypter, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: keyAlgorithm, Key: publicKey}, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create jwe encrypter: %w", err)
	}

	return &JWESessionCodec{jwtSessionCodec: &codec, encrypter: encrypter, privateKey: privateKey, keyAlgorithm: keyAlgorithm}, nil
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
	jwe, err := jose.ParseEncrypted(encrypted, []jose.KeyAlgorithm{c.keyAlgorithm}, []jose.ContentEncryption{jose.A128GCM})
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

func jweKeyAlgorithmForPublicKey(publicKey crypto.PublicKey) (jose.KeyAlgorithm, error) {
	switch publicKey.(type) {
	case *rsa.PublicKey:
		return jose.RSA_OAEP, nil
	case *ecdsa.PublicKey:
		return jose.ECDH_ES_A128KW, nil
	default:
		return "", fmt.Errorf("unsupported public key type for JWE: %T", publicKey)
	}
}
