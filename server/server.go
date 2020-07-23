package server

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

const fetchMetadataTimeout = 30 * time.Second

type Config struct {
	Version                 bool              `usage:"show version and exit" env:""`
	Bind                    string            `default:":8080" usage:"[host:port] to bind for serving HTTP"`
	BaseUrl                 string            `usage:"External [URL] of this proxy"`
	BackendUrl              string            `usage:"[URL] of the backend being proxied"`
	IdpMetadataUrl          string            `usage:"[URL] of the IdP's metadata XML, can be a local file by specifying the file:// scheme"`
	IdpCaPath               string            `usage:"Optional [path] to a CA certificate PEM file for the IdP"`
	NameIdFormat            string            `usage:"One of unspecified, transient, email, or persistent to use a standard format or give a full URN of the name ID format" default:"transient"`
	SpKeyPath               string            `default:"saml-auth-proxy.key" usage:"The [path] to the X509 private key PEM file for this SP"`
	SpCertPath              string            `default:"saml-auth-proxy.cert" usage:"The [path] to the X509 public certificate PEM file for this SP"`
	NameIdMapping           string            `usage:"Name of the request [header] to convey the SAML nameID/subject"`
	AttributeHeaderMappings map[string]string `usage:"Comma separated list of [attribute=header] pairs mapping SAML IdP response attributes to forwarded request header"`
	NewAuthWebhookUrl       string            `usage:"[URL] of webhook that will get POST'ed when a new authentication is processed"`
	AuthorizeAttribute      string            `usage:"Enables authorization and specifies the [attribute] to check for authorized values"`
	AuthorizeValues         []string          `usage:"If enabled, comma separated list of [values] that must be present in the authorize attribute"`
	CookieMaxAge            time.Duration     `usage:"Specifies the amount of time the authentication token will remain valid" default:"2h"`
	AllowIdpInitiated       bool              `usage:"If set, allows for IdP initiated authentication flow"`
}

func Start(ctx context.Context, cfg *Config) error {
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

	// This is redundant with RequestTracker created in samlsp.New, but prepares for deprecation switch
	middleware.RequestTracker = samlsp.DefaultRequestTracker(samlsp.Options{
		URL: *rootUrl,
		Key: keyPair.PrivateKey.(*rsa.PrivateKey),
	}, &middleware.ServiceProvider)

	// This is redundant with Session created in samlsp.New, but prepares for deprecation switch
	// Library is still using same Options struct for all of these
	// ...so the fields are flagged as deprecated but library
	middleware.Session = samlsp.DefaultSessionProvider(samlsp.Options{
		URL:          *rootUrl,
		Key:          keyPair.PrivateKey.(*rsa.PrivateKey),
		CookieMaxAge: cfg.CookieMaxAge,
		CookieDomain: rootUrl.Hostname(),
	})

	proxy, err := NewProxy(cfg)
	if err != nil {
		return fmt.Errorf("failed to create proxy: %w", err)
	}

	app := http.HandlerFunc(proxy.handler)
	http.Handle("/saml/", middleware)
	http.Handle("/_health", http.HandlerFunc(proxy.health))
	http.Handle("/", middleware.RequireAccount(app))

	log.Printf("Serving requests for %s -> %s at %s",
		cfg.BaseUrl, cfg.BackendUrl, cfg.Bind)
	return http.ListenAndServe(cfg.Bind, nil)
}

func fetchMetadata(ctx context.Context, client *http.Client, idpMetadataUrl *url.URL) (*saml.EntityDescriptor, error) {
	if idpMetadataUrl.Scheme == "file" {
		data, err := ioutil.ReadFile(idpMetadataUrl.Path)
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

	certs, err := ioutil.ReadFile(idpCaFile)
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
