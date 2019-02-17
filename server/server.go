package server

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"github.com/crewjam/saml/samlsp"
	"github.com/pkg/errors"
	"log"
	"net/http"
	"net/url"
)

type Config struct {
	Bind                    string
	BaseUrl                 string
	BackendUrl              string
	IdpMetadataUrl          string
	SpKeyPath               string
	SpCertPath              string
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

	samlSP, err := samlsp.New(samlsp.Options{
		URL:            *rootUrl,
		Key:            keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:    keyPair.Leaf,
		IDPMetadataURL: idpMetadataUrl,
	})
	if err != nil {
		return errors.Wrap(err, "Failed to initialize SP")
	}

	proxy, err := NewProxy(cfg)
	if err != nil {
		return errors.Wrap(err, "Failed to create proxy")
	}

	app := http.HandlerFunc(proxy.handler)
	http.Handle("/saml/", samlSP)
	http.Handle("/", samlSP.RequireAccount(app))

	log.Printf("Serving requests for %s at %s", cfg.BaseUrl, cfg.Bind)
	return http.ListenAndServe(cfg.Bind, nil)
}
