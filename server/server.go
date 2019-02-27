package server

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/pkg/errors"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

type Config struct {
	Bind                    string
	BaseUrl                 string
	BackendUrl              string
	IdpMetadataUrl          string
	IdpCaFile               string
	NameIdFormat            string
	SpKeyPath               string
	SpCertPath              string
	NameIdHeaderMapping     string
	AttributeHeaderMappings map[string]string
	NewAuthWebhookUrl       string
}

func Start(cfg *Config) error {
	keyPair, err := tls.LoadX509KeyPair(cfg.SpCertPath, cfg.SpKeyPath)
	if err != nil {
		return errors.Wrap(err, "Failed to load SP key and certificate")
	}

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return errors.Wrap(err, "Failed to parse SP certificate")
	}

	idpMetadataUrl, err := url.Parse(cfg.IdpMetadataUrl)
	if err != nil {
		return errors.Wrap(err, "Failed to parse IdP metdata URL")
	}

	rootUrl, err := url.Parse(cfg.BaseUrl)
	if err != nil {
		return errors.Wrap(err, "Failed to parse base URL")
	}

	httpClient, err := setupHttpClient(cfg.IdpCaFile)
	if err != nil {
		return errors.Wrap(err, "Failed to setup HTTP client")
	}

	samlSP, err := samlsp.New(samlsp.Options{
		URL:            *rootUrl,
		Key:            keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:    keyPair.Leaf,
		IDPMetadataURL: idpMetadataUrl,
		CookieDomain:   rootUrl.Hostname(),
		HTTPClient:     httpClient,
	})
	if err != nil {
		return errors.Wrap(err, "Failed to initialize SP")
	}

	switch cfg.NameIdFormat {
	case "unspecified":
		samlSP.ServiceProvider.AuthnNameIDFormat = saml.UnspecifiedNameIDFormat
	case "transient":
		samlSP.ServiceProvider.AuthnNameIDFormat = saml.TransientNameIDFormat
	case "email":
		samlSP.ServiceProvider.AuthnNameIDFormat = saml.EmailAddressNameIDFormat
	case "persistent":
		samlSP.ServiceProvider.AuthnNameIDFormat = saml.PersistentNameIDFormat
	default:
		samlSP.ServiceProvider.AuthnNameIDFormat = saml.NameIDFormat(cfg.NameIdFormat)
	}

	proxy, err := NewProxy(cfg)
	if err != nil {
		return errors.Wrap(err, "Failed to create proxy")
	}

	app := http.HandlerFunc(proxy.handler)
	http.Handle("/saml/", samlSP)
	http.Handle("/_health", http.HandlerFunc(proxy.health))
	http.Handle("/", samlSP.RequireAccount(app))

	log.Printf("Serving requests for %s at %s", cfg.BaseUrl, cfg.Bind)
	return http.ListenAndServe(cfg.Bind, nil)
}

func setupHttpClient(idpCaFile string) (*http.Client, error) {
	if idpCaFile == "" {
		return nil, nil
	}

	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	certs, err := ioutil.ReadFile(idpCaFile)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to read IdP CA file")
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
