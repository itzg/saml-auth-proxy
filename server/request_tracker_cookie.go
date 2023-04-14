package server

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

// Extends samlsp.CookieRequestTracker to add CookieDomain configuration.
type CookieRequestTracker struct {
	samlsp.CookieRequestTracker

	CookieDomain     string
	StaticRelayState string
}

func minOfInts(x, y int) int {
	if x < y {
		return x
	} else {
		return y
	}
}

// Source: https://github.com/crewjam/saml/blob/5e0ffd290abf0be7dfd4f8279e03a963071544eb/samlsp/request_tracker_cookie.go#L28-58
// Changes:
// - Adds host in request URI
// - Adds CookieDomain config in http.SetCookie
// - Handles X-Forwarded headers
func (t CookieRequestTracker) TrackRequest(w http.ResponseWriter, r *http.Request, samlRequestID string) (string, error) {
	var redirectURI *url.URL
	if r.Header.Get(HeaderForwardedHost) != "" && r.Header.Get(HeaderForwardedURI) != "" && r.Header.Get(HeaderForwardedMethod) != "" {
		// When X-Forwarded headers exist, use it
		redirectURI, _ = url.Parse(fmt.Sprintf("%s://%s%s", r.Header.Get(HeaderForwardedProto), r.Header.Get(HeaderForwardedHost), r.Header.Get(HeaderForwardedURI)))
	} else {
		redirectURI, _ = url.Parse(r.URL.String()) // Clone
		redirectURI.Host = r.Host
	}

	trackedRequest := samlsp.TrackedRequest{
		Index:         base64.RawURLEncoding.EncodeToString(randomBytes(42)),
		SAMLRequestID: samlRequestID,
		URI:           redirectURI.String(),
	}

	if t.StaticRelayState != "" {
		trackedRequest.Index = t.StaticRelayState[0:minOfInts(80, len(t.StaticRelayState))]
	} else if t.RelayStateFunc != nil {
		relayState := t.RelayStateFunc(w, r)
		if relayState != "" {
			trackedRequest.Index = relayState
		}
	}

	signedTrackedRequest, err := t.Codec.Encode(trackedRequest)
	if err != nil {
		return "", err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     t.NamePrefix + trackedRequest.Index,
		Value:    signedTrackedRequest,
		MaxAge:   int(t.MaxAge.Seconds()),
		Domain:   t.CookieDomain,
		HttpOnly: true,
		SameSite: t.SameSite,
		Secure:   t.ServiceProvider.AcsURL.Scheme == "https",
		Path:     t.ServiceProvider.AcsURL.Path,
	})

	return trackedRequest.Index, nil
}

// Source: https://github.com/crewjam/saml/blob/5e0ffd290abf0be7dfd4f8279e03a963071544eb/samlsp/util.go#L9-L16
func randomBytes(n int) []byte {
	rv := make([]byte, n)

	if _, err := io.ReadFull(saml.RandReader, rv); err != nil {
		panic(err)
	}
	return rv
}
