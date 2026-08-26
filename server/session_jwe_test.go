package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

func TestJWESessionCodec(t *testing.T) {
	// Generate a new RSA key pair for testing
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key pair: %v", err)
	}

	// Create a base JWTSessionCodec
	baseURL, _ := url.Parse("http://localhost") // baseURL is required
	jwtCodec := samlsp.DefaultSessionCodec(samlsp.Options{Key: key, URL: *baseURL})

	// Create the JWESessionCodec
	jweCodec, err := NewJWESessionCodec(jwtCodec, key.Public(), key)
	if err != nil {
		t.Fatalf("failed to create JWESessionCodec: %v", err)
	}

	// Create a sample assertion
	assertion := &saml.Assertion{
		Subject: &saml.Subject{
			NameID: &saml.NameID{
				Value: "testuser",
			},
		},
		AttributeStatements: []saml.AttributeStatement{
			{
				Attributes: []saml.Attribute{
					{
						Name:   "email",
						Values: []saml.AttributeValue{{Value: "test@example.com"}},
					},
					{
						Name:   "groups",
						Values: []saml.AttributeValue{{Value: "admin"}, {Value: "users"}},
					},
				},
			},
		},
		AuthnStatements: []saml.AuthnStatement{
			{
				SessionIndex: "some-session-index",
				AuthnInstant: time.Now(),
			},
		},
	}

	// Create a new session from the assertion
	session, err := jweCodec.New(assertion)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Encode the session
	encoded, err := jweCodec.Encode(session)
	if err != nil {
		t.Fatalf("Failed to encode session: %v", err)
	}
	if encoded == "" {
		t.Error("Encoded session should not be empty")
	}

	// Decode the session
	decodedSession, err := jweCodec.Decode(encoded)
	if err != nil {
		t.Fatalf("Failed to decode session: %v", err)
	}
	if decodedSession == nil {
		t.Error("Decoded session should not be nil")
	}

	// Verify the decoded session
	claim, ok := decodedSession.(samlsp.JWTSessionClaims)
	if !ok {
		t.Fatal("Decoded session is not a JWTSessionClaims")
	}

	if claim.Subject != "testuser" {
		t.Errorf("Expected subject 'testuser', got '%s'", claim.Subject)
	}

	if claim.Attributes.Get("SessionIndex") != "some-session-index" {
		t.Errorf("Expected SessionIndex 'some-session-index', got '%s'", claim.Attributes.Get("SessionIndex"))
	}

	if claim.Attributes.Get("email") != "test@example.com" {
		t.Errorf("Expected email 'test@example.com', got '%s'", claim.Attributes.Get("email"))
	}

	// groups
	groups := claim.Attributes["groups"]
	if len(groups) != 2 {
		t.Errorf("Expected 2 groups, got %d", len(groups))
	}
	if !slices.Contains(groups, "admin") || !slices.Contains(groups, "users") {
		t.Errorf("Expected groups 'admin' and 'users', got %v", groups)
	}
}

func TestJWESessionCodec_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key pair: %v", err)
	}

	baseURL, _ := url.Parse("http://localhost") // baseURL is required
	jwtCodec := samlsp.DefaultSessionCodec(samlsp.Options{Key: key, URL: *baseURL})

	jweCodec, err := NewJWESessionCodec(jwtCodec, key.Public(), key)
	if err != nil {
		t.Fatalf("failed to create JWESessionCodec: %v", err)
	}

	assertion := &saml.Assertion{
		Subject: &saml.Subject{
			NameID: &saml.NameID{
				Value: "ecdsa-user",
			},
		},
		AuthnStatements: []saml.AuthnStatement{
			{
				SessionIndex: "ecdsa-session-index",
				AuthnInstant: time.Now(),
			},
		},
	}

	session, err := jweCodec.New(assertion)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	encoded, err := jweCodec.Encode(session)
	if err != nil {
		t.Fatalf("Failed to encode session: %v", err)
	}
	if encoded == "" {
		t.Error("Encoded session should not be empty")
	}

	decodedSession, err := jweCodec.Decode(encoded)
	if err != nil {
		t.Fatalf("Failed to decode session: %v", err)
	}
	if decodedSession == nil {
		t.Error("Decoded session should not be nil")
	}

	claim, ok := decodedSession.(samlsp.JWTSessionClaims)
	if !ok {
		t.Fatal("Decoded session is not a JWTSessionClaims")
	}

	if claim.Subject != "ecdsa-user" {
		t.Errorf("Expected subject 'ecdsa-user', got '%s'", claim.Subject)
	}
}
