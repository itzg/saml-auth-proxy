package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/crewjam/saml/samlsp"
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
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
		return nil, errors.Wrap(err, "Failed to parse backend URL")
	}

	proxy := &proxy{
		config:        cfg,
		client:        &http.Client{},
		backendUrl:    backendUrl,
		newTokenCache: cache.New(newTokenCacheExpiration, newTokenCacheCleanupInterval),
	}

	return proxy, nil
}

func (p *proxy) health(respOutWriter http.ResponseWriter, reqIn *http.Request) {
	respOutWriter.Header().Set("Content-Type", "text/plain")
	respOutWriter.WriteHeader(200)
	respOutWriter.Write([]byte("OK"))
}

func (p *proxy) handler(respOutWriter http.ResponseWriter, reqIn *http.Request) {

	authToken := samlsp.Token(reqIn.Context())

	authUsing, authorized := p.authorized(authToken, reqIn)
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

	p.checkForNewAuth(authToken)

	if p.config.AttributeHeaderMappings != nil {
		for attr, hdr := range p.config.AttributeHeaderMappings {
			if values, ok := authToken.Attributes[attr]; ok {
				for _, value := range values {
					reqOut.Header.Add(hdr, value)
				}
			}
		}
	}
	if p.config.NameIdHeaderMapping != "" {
		reqOut.Header.Set(p.config.NameIdHeaderMapping,
			authToken.StandardClaims.Subject)
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
	defer respIn.Body.Close()
	copyHeaders(respOutWriter.Header(), respIn.Header)
	respOutWriter.WriteHeader(respIn.StatusCode)
	io.Copy(respOutWriter, respIn.Body)
}

func (p *proxy) checkForNewAuth(authToken *samlsp.AuthorizationToken) {
	if p.config.NewAuthWebhookUrl != "" && authToken.IssuedAt >= time.Now().Unix()-1 {
		err := p.newTokenCache.Add(authToken.Id, authToken, cache.DefaultExpiration)
		if err == nil {
			log.Printf("Issued new authentication token: %+v", authToken)

			var postBody bytes.Buffer
			encoder := json.NewEncoder(&postBody)
			err := encoder.Encode(authToken.Attributes)
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
func (p *proxy) authorized(token *samlsp.AuthorizationToken, request *http.Request) (string, bool) {
	if p.config.AuthorizeAttribute != "" {
		values, exists := token.Attributes[p.config.AuthorizeAttribute]
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
