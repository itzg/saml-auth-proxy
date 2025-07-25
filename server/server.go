package server

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"go.uber.org/zap"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

const fetchMetadataTimeout = 30 * time.Second

func Start(ctx context.Context, listener net.Listener, logger *zap.Logger, cfg *Config) error {
	keyPair, err := tls.LoadX509KeyPair(cfg.SpCertPath, cfg.SpKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load SP key and certificate: %w", err)
	}

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse SP certificate: %w", err)
	}

	idpMetadataUrl, err := url.Parse(cfg.IdpMetadataUrl)
	if err != nil {
		return fmt.Errorf("failed to parse IdP metdata URL: %w", err)
	}

	rootUrl, err := url.Parse(cfg.BaseUrl)
	if err != nil {
		return fmt.Errorf("failed to parse base URL: %w", err)
	}

	httpClient, err := setupHttpClient(cfg.IdpCaPath)
	if err != nil {
		return fmt.Errorf("failed to setup HTTP client: %w", err)
	}

	samlOpts := samlsp.Options{
		URL:               *rootUrl,
		Key:               keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:       keyPair.Leaf,
		AllowIDPInitiated: cfg.AllowIdpInitiated,
		SignRequest:       cfg.SignRequests,
	}
	if cfg.EntityID != "" {
		samlOpts.EntityID = cfg.EntityID
	}

	samlOpts.IDPMetadata, err = fetchMetadata(ctx, httpClient, idpMetadataUrl)
	if err != nil {
		return fmt.Errorf("failed to fetch/load IdP metadata: %w", err)
	}

	middleware, err := samlsp.New(samlOpts)
	if err != nil {
		return fmt.Errorf("failed to initialize SP: %w", err)
	}

	switch cfg.NameIdFormat {
	case "unspecified":
		middleware.ServiceProvider.AuthnNameIDFormat = saml.UnspecifiedNameIDFormat
	case "transient":
		middleware.ServiceProvider.AuthnNameIDFormat = saml.TransientNameIDFormat
	case "email":
		middleware.ServiceProvider.AuthnNameIDFormat = saml.EmailAddressNameIDFormat
	case "persistent":
		middleware.ServiceProvider.AuthnNameIDFormat = saml.PersistentNameIDFormat
	default:
		middleware.ServiceProvider.AuthnNameIDFormat = saml.NameIDFormat(cfg.NameIdFormat)
	}

	var cookieDomain = cfg.CookieDomain
	if cookieDomain == "" {
		cookieDomain = rootUrl.Hostname()
	}
	middleware.RequestTracker = CookieRequestTracker{
		CookieRequestTracker: samlsp.DefaultRequestTracker(samlsp.Options{
			URL: *rootUrl,
			Key: keyPair.PrivateKey.(*rsa.PrivateKey),
		}, &middleware.ServiceProvider),
		CookieDomain:          cookieDomain,
		StaticRelayState:      cfg.StaticRelayState,
		TrustForwardedHeaders: cfg.AuthVerify,
	}
	cookieSessionProvider := samlsp.DefaultSessionProvider(samlOpts)
	cookieSessionProvider.Name = cfg.CookieName
	cookieSessionProvider.Domain = cookieDomain
	cookieSessionProvider.MaxAge = cfg.CookieMaxAge
	codec := samlsp.DefaultSessionCodec(samlOpts)
	codec.MaxAge = cfg.CookieMaxAge
	cookieSessionProvider.Codec = codec

	if cfg.EncryptJWT {
		jweSessionCodec, err := NewJWESessionCodec(cookieSessionProvider.Codec)
		if err != nil {
			return fmt.Errorf("failed to create jwe session codec: %w", err)
		}
		cookieSessionProvider.Codec = jweSessionCodec
	}

	if cfg.InitiateSessionPath != "" {
		middleware.Session = NewInitAnonymousSessionProvider(logger, cfg.InitiateSessionPath, cookieSessionProvider)
	} else {
		middleware.Session = cookieSessionProvider
	}

	proxy, err := NewProxy(logger, cfg)
	if err != nil {
		return fmt.Errorf("failed to create proxy: %w", err)
	}

	app := http.HandlerFunc(proxy.handler)
	if cfg.AuthVerify {
		http.Handle(cfg.AuthVerifyPath, middleware.RequireAccount(http.HandlerFunc(noContentHandler)))
	}

	http.Handle("/saml/sign_in", http.HandlerFunc(middleware.HandleStartAuthFlow))
	http.Handle("/saml/", middleware)
	http.Handle("/_health", http.HandlerFunc(proxy.health))
	http.Handle("/", middleware.RequireAccount(app))

	logger.
		With(zap.String("baseUrl", cfg.BaseUrl)).
		With(zap.String("backendUrl", cfg.BackendUrl)).
		With(zap.String("binding", cfg.Bind)).
		Info("Serving requests")
	return http.Serve(listener, nil)
}

func fetchMetadata(ctx context.Context, client *http.Client, idpMetadataUrl *url.URL) (*saml.EntityDescriptor, error) {
	if idpMetadataUrl.Scheme == "file" {
		data, err := os.ReadFile(idpMetadataUrl.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to read IdP metadata file.: %w", err)
		}
		idpMetadata := &saml.EntityDescriptor{}
		err = xml.Unmarshal(data, idpMetadata)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal IdP metadata XML.: %w", err)
		}
		return idpMetadata, nil
	} else {
		reqCtx, _ := context.WithTimeout(ctx, fetchMetadataTimeout)
		return samlsp.FetchMetadata(reqCtx, client, *idpMetadataUrl)
	}
}

func setupHttpClient(idpCaFile string) (*http.Client, error) {
	if idpCaFile == "" {
		return http.DefaultClient, nil
	}

	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	certs, err := os.ReadFile(idpCaFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read IdP CA file: %w", err)
	}

	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		log.Println("INF No certs appended, using system certs only")
	}

	config := &tls.Config{
		RootCAs: rootCAs,
	}

	tr := &http.Transport{TLSClientConfig: config}
	client := &http.Client{Transport: tr}

	return client, nil
}

// HTTP handler that replies to each request with a “204 no content”.
func noContentHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}
