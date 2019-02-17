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

const newTokenCacheExpiration = 5 * time.Second
const newTokenCacheCleanupInterval = 1 * time.Minute

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

func (p *proxy) handler(respOutWriter http.ResponseWriter, reqIn *http.Request) {

	resolved, err := p.backendUrl.Parse(reqIn.URL.Path)
	if err != nil {
		log.Printf("ERR failed to resolve backend URL from %s: %s", reqIn.URL.Path, err.Error())

		respOutWriter.WriteHeader(500)
		_, _ = respOutWriter.Write([]byte(fmt.Sprintf("Failed to resolve backend URL: %s", err.Error())))
		return
	}

	reqOut, err := http.NewRequest(reqIn.Method, resolved.String(), reqIn.Body)

	authToken := samlsp.Token(reqIn.Context())

	p.checkForNewAuth(authToken)

	if p.config.AttributeHeaderMappings != nil {
		for attr, hdr := range p.config.AttributeHeaderMappings {
			reqOut.Header.Set(hdr, authToken.Attributes.Get(attr))
		}
	}
	copyHeaders(reqOut.Header, reqIn.Header)
	reqOut.Header.Set("X-Forwarded-Host", reqIn.Host)
	remoteHost, _, err := net.SplitHostPort(reqIn.RemoteAddr)
	if err == nil {
		reqOut.Header.Add("X-Forwarded-For", remoteHost)
	} else {
		log.Printf("ERR unable to parse host and port from %s: %s", reqIn.RemoteAddr, err.Error())
	}
	protoParts := strings.Split(reqIn.Proto, "/")
	reqOut.Header.Set("X-Forwarded-Proto", strings.ToLower(protoParts[0]))

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
				log.Printf("ERR uanble to encode auth token attributes: %s", err.Error())
			}
		}
	}
}

func copyHeaders(dst http.Header, src http.Header) {
	for k, values := range src {
		for _, value := range values {
			dst.Add(k, value)
		}
	}
}
