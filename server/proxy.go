package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"

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
	HeaderForwardedURI    = "X-Forwarded-Uri"
	HeaderForwardedMethod = "X-Forwarded-Method"
)

type proxy struct {
	config        *Config
	backendUrl    *url.URL
	client        *http.Client
	newTokenCache *cache.Cache
	logger        *zap.Logger
}

func NewProxy(logger *zap.Logger, cfg *Config) (*proxy, error) {
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
		logger:        logger,
	}

	return proxy, nil
}

func (p *proxy) health(respOutWriter http.ResponseWriter, _ *http.Request) {
	respOutWriter.Header().Set("Content-Type", "text/plain")
	respOutWriter.WriteHeader(200)
	_, err := respOutWriter.Write([]byte("OK"))
	if err != nil {
		p.logger.
			With(zap.Error(err)).
			Error("failed to write health response body")
	}
}

func (p *proxy) handler(respOutWriter http.ResponseWriter, reqIn *http.Request) {

	sessionClaims, ok := getSessionClaims(reqIn)
	if !ok {
		p.logger.Error("session is not expected type")
		respOutWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	authUsing, authorized := p.authorized(sessionClaims)
	if !authorized {
		p.logger.Debug("Responding Unauthorized")
		respOutWriter.WriteHeader(http.StatusUnauthorized)
		return
	}

	if p.config.AuthVerify && reqIn.URL.Path == p.config.AuthVerifyPath {
		p.logger.
			With(zap.String("remoteAddr", reqIn.RemoteAddr)).
			Debug("Responding with 204 to auth verify request")
		p.addHeaders(sessionClaims, respOutWriter.Header())
		respOutWriter.WriteHeader(204)
		return
	}

	resolved, err := p.backendUrl.Parse(reqIn.URL.Path)
	if err != nil {
		p.logger.
			With(zap.String("urlPath", reqIn.URL.Path)).
			With(zap.Error(err)).
			Error("failed to resolve backend URL")

		respOutWriter.WriteHeader(500)
		_, _ = respOutWriter.Write([]byte(fmt.Sprintf("Failed to resolve backend URL: %s", err.Error())))
		return
	}
	resolved.RawQuery = reqIn.URL.RawQuery

	reqOut, err := http.NewRequest(reqIn.Method, resolved.String(), reqIn.Body)
	if err != nil {
		p.logger.
			With(zap.String("method", reqIn.Method)).
			With(zap.Any("url", reqIn.URL)).
			With(zap.Error(err)).
			Error("unable to create new request")
		respOutWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	copyHeaders(reqOut.Header, reqIn.Header)

	reqOut.Header.Del("Cookie")
	cookies := reqIn.Cookies()
	for _, cookie := range cookies {
		if cookie.Name != p.config.CookieName {
			reqOut.AddCookie(cookie)
		}
	}

	if sessionClaims != nil {
		p.checkForNewAuth(sessionClaims)

		p.addHeaders(sessionClaims, reqOut.Header)

		if p.config.NameIdMapping != "" {
			reqOut.Header.Set(p.config.NameIdMapping,
				sessionClaims.Subject)
		}
	}

	reqOut.Header.Set(HeaderForwardedHost, reqIn.Host)
	remoteHost, _, err := net.SplitHostPort(reqIn.RemoteAddr)
	if err == nil {
		reqOut.Header.Add(HeaderForwardedFor, remoteHost)
	} else {
		p.logger.
			With(zap.Error(err)).
			With(zap.String("remoteAddr", reqIn.RemoteAddr)).
			Error("unable to parse host and port")
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
		p.logger.
			With(zap.Error(err)).
			Error("failed to transfer backend response body")
	}
}

func getSessionClaims(reqIn *http.Request) (*samlsp.JWTSessionClaims, bool) {
	session := samlsp.SessionFromContext(reqIn.Context())
	if session == nil {
		return nil, true
	}

	sessionClaims, ok := session.(samlsp.JWTSessionClaims)
	return &sessionClaims, ok
}

func (p *proxy) addHeaders(sessionClaims *samlsp.JWTSessionClaims, headers http.Header) {
	if sessionClaims == nil {
		return
	}

	if p.config.AttributeHeaderMappings != nil {
		for attr, hdr := range p.config.AttributeHeaderMappings {
			if values, ok := sessionClaims.GetAttributes()[attr]; ok {
				for _, value := range values {
					headers.Add(hdr, value)
				}
			}
		}
	}

	if p.config.AttributeHeaderWildcard != "" {
		for attr, values := range sessionClaims.GetAttributes() {
			for _, value := range values {
				headers.Add(p.config.AttributeHeaderWildcard+attr, value)
			}
		}
	}
}

func (p *proxy) checkForNewAuth(sessionClaims *samlsp.JWTSessionClaims) {
	if p.config.NewAuthWebhookUrl != "" && sessionClaims.IssuedAt >= time.Now().Unix()-1 {
		err := p.newTokenCache.Add(sessionClaims.Id, sessionClaims, cache.DefaultExpiration)
		if err == nil {
			p.logger.
				With(zap.Any("sessionClaims", sessionClaims)).
				Info("Issued new authentication token")

			var postBody bytes.Buffer
			encoder := json.NewEncoder(&postBody)
			err := encoder.Encode(sessionClaims.GetAttributes())
			if err == nil {
				_, err := http.Post(p.config.NewAuthWebhookUrl, "application/json", &postBody)
				if err != nil {
					p.logger.
						With(zap.Error(err)).
						Error("unable to post new auth webhook")
				}
			} else {
				p.logger.
					With(zap.Error(err)).
					Error("unable to encode auth token attributes")
			}
		}
	}
}

// authorized returns a boolean indication if the request is authorized.
// The initial string return value is an attribute=value pair that was used to authorize the request.
// If authorization was not configured the returned string is empty.
func (p *proxy) authorized(sessionClaims *samlsp.JWTSessionClaims) (string, bool) {
	if p.config.AuthorizeAttribute != "" {
		if sessionClaims == nil {
			return "", false
		}

		values, exists := sessionClaims.GetAttributes()[p.config.AuthorizeAttribute]
		if !exists {
			p.logger.Debug("AuthorizeAttribute not present in session claims")
			return "", false
		}

		for _, value := range values {
			for _, expected := range p.config.AuthorizeValues {
				if value == expected {
					return fmt.Sprintf("%s=%s", p.config.AuthorizeAttribute, value), true
				}
			}
		}

		p.logger.
			With(zap.Strings("values", values)).
			Debug("AuthorizeAttribute did not match required value")
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
