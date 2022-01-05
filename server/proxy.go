package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml/samlsp"
	"github.com/patrickmn/go-cache"
)

const (
	newTokenCacheExpiration      = 5 * time.Second
	newTokenCacheCleanupInterval = 1 * time.Minute
)

const (
	HeaderAuthorizedUsing = "X-Authorized-Using"
	HeaderForwardedProto  = "X-Forwarded-Proto"
	HeaderForwardedFor    = "X-Forwarded-For"
	HeaderForwardedHost   = "X-Forwarded-Host"
)

type proxy struct {
	config        *Config
	backendUrl    *url.URL
	client        *http.Client
	newTokenCache *cache.Cache
}

func NewProxy(cfg *Config) (*proxy, error) {
	backendUrl, err := url.Parse(cfg.BackendUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse backend URL: %w", err)
	}

	client := &http.Client{
		// don't follow redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	proxy := &proxy{
		config:        cfg,
		client:        client,
		backendUrl:    backendUrl,
		newTokenCache: cache.New(newTokenCacheExpiration, newTokenCacheCleanupInterval),
	}

	return proxy, nil
}

func (p *proxy) health(respOutWriter http.ResponseWriter, _ *http.Request) {
	respOutWriter.Header().Set("Content-Type", "text/plain")
	respOutWriter.WriteHeader(200)
	_, err := respOutWriter.Write([]byte("OK"))
	if err != nil {
		log.Printf("ERR failed to write health response body: %s", err.Error())
	}
}

func (p *proxy) handler(respOutWriter http.ResponseWriter, reqIn *http.Request) {

	session := samlsp.SessionFromContext(reqIn.Context())
	sessionClaims, ok := session.(samlsp.JWTSessionClaims)
	if !ok {
		log.Printf("ERR session is not expected type")
		respOutWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	authUsing, authorized := p.authorized(&sessionClaims)
	if !authorized {
		respOutWriter.WriteHeader(http.StatusUnauthorized)
		return
	}

	resolved, err := p.backendUrl.Parse(reqIn.URL.Path)
	if err != nil {
		log.Printf("ERR failed to resolve backend URL from %s: %s", reqIn.URL.Path, err.Error())

		respOutWriter.WriteHeader(500)
		_, _ = respOutWriter.Write([]byte(fmt.Sprintf("Failed to resolve backend URL: %s", err.Error())))
		return
	}
	resolved.RawQuery = reqIn.URL.RawQuery

	reqOut, err := http.NewRequest(reqIn.Method, resolved.String(), reqIn.Body)
	if err != nil {
		log.Printf("ERR unable to create new request for %s %s: %s", reqIn.Method, reqIn.URL, err)
		respOutWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	copyHeaders(reqOut.Header, reqIn.Header)

	reqOut.Header.Del("Cookie")
	cookies := reqIn.Cookies()
	for _, cookie := range cookies {
		if cookie.Name != tokenCookieName {
			reqOut.AddCookie(cookie);
		}
	}

	p.checkForNewAuth(&sessionClaims)

	if p.config.AttributeHeaderMappings != nil {
		for attr, hdr := range p.config.AttributeHeaderMappings {
			if values, ok := sessionClaims.GetAttributes()[attr]; ok {
				for _, value := range values {
					reqOut.Header.Add(hdr, value)
				}
			}
		}
	}

	if p.config.AttributeHeaderWildcard != "" {
		for attr, values := range sessionClaims.GetAttributes() {
			for _, value := range values {
				reqOut.Header.Add(p.config.AttributeHeaderWildcard+attr, value)
			}
		}
	}

	if p.config.NameIdMapping != "" {
		reqOut.Header.Set(p.config.NameIdMapping,
			sessionClaims.Subject)
	}

	reqOut.Header.Set(HeaderForwardedHost, reqIn.Host)
	remoteHost, _, err := net.SplitHostPort(reqIn.RemoteAddr)
	if err == nil {
		reqOut.Header.Add(HeaderForwardedFor, remoteHost)
	} else {
		log.Printf("ERR unable to parse host and port from %s: %s", reqIn.RemoteAddr, err.Error())
	}
	protoParts := strings.Split(reqIn.Proto, "/")
	reqOut.Header.Set(HeaderForwardedProto, strings.ToLower(protoParts[0]))
	if authUsing != "" {
		reqOut.Header.Set(HeaderAuthorizedUsing, authUsing)
	}

	respIn, err := p.client.Do(reqOut)
	if err != nil {
		respOutWriter.WriteHeader(http.StatusBadGateway)
		_, _ = respOutWriter.Write([]byte(err.Error()))
		return
	}
	defer respIn.Body.Close()
	copyHeaders(respOutWriter.Header(), respIn.Header)
	respOutWriter.WriteHeader(respIn.StatusCode)
	_, err = io.Copy(respOutWriter, respIn.Body)
	if err != nil {
		log.Printf("ERR failed to transfer backend response body: %s", err.Error())
	}
}

func (p *proxy) checkForNewAuth(sessionClaims *samlsp.JWTSessionClaims) {
	if p.config.NewAuthWebhookUrl != "" && sessionClaims.IssuedAt >= time.Now().Unix()-1 {
		err := p.newTokenCache.Add(sessionClaims.Id, sessionClaims, cache.DefaultExpiration)
		if err == nil {
			log.Printf("Issued new authentication token: %+v", sessionClaims)

			var postBody bytes.Buffer
			encoder := json.NewEncoder(&postBody)
			err := encoder.Encode(sessionClaims.GetAttributes())
			if err == nil {
				_, err := http.Post(p.config.NewAuthWebhookUrl, "application/json", &postBody)
				if err != nil {
					log.Printf("ERR unable to post new auth webhook: %s", err.Error())
				}
			} else {
				log.Printf("ERR unable to encode auth token attributes: %s", err.Error())
			}
		}
	}
}

// authorized returns an boolean indication if the request is authorized.
// The initial string return value is an attribute=value pair that was used to authorize the request.
// If authorization was not configured the returned string is empty.
func (p *proxy) authorized(sessionClaims *samlsp.JWTSessionClaims) (string, bool) {
	if p.config.AuthorizeAttribute != "" {
		values, exists := sessionClaims.GetAttributes()[p.config.AuthorizeAttribute]
		if !exists {
			return "", false
		}

		for _, value := range values {
			for _, expected := range p.config.AuthorizeValues {
				if value == expected {
					return fmt.Sprintf("%s=%s", p.config.AuthorizeAttribute, value), true
				}
			}
		}

		return "", false
	} else {
		return "", true
	}
}

func copyHeaders(dst http.Header, src http.Header) {
	for k, values := range src {
		for _, value := range values {
			dst.Add(k, value)
		}
	}
}
