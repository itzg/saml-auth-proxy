package server

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/pkg/errors"
)

type Config struct {
	Version                 bool              `usage:"show version and exit" env:""`
	Bind                    string            `default:":8080" usage:"[host:port] to bind for serving HTTP"`
	BaseUrl                 string            `usage:"External [URL] of this proxy"`
	BackendUrl              string            `usage:"[URL] of the backend being proxied"`
	IdpMetadataUrl          string            `usage:"[URL] of the IdP's metadata XML, can be a local file by specifying the file:// scheme"`
	IdpCaPath               string            `usage:"Optional [path] to a CA certificate PEM file for the IdP"`
	NameIdFormat            string            `usage:"One of unspecified, transient (default), email, or persistent to use a standard format or give a full URN of the name ID format"`
	SpKeyPath               string            `default:"saml-auth-proxy.key" usage:"The [path] to the X509 private key PEM file for this SP"`
	SpCertPath              string            `default:"saml-auth-proxy.cert" usage:"The [path] to the X509 public certificate PEM file for this SP"`
	NameIdMapping           string            `usage:"Name of the request [header] to convey the SAML nameID/subject"`
	AttributeHeaderMappings map[string]string `usage:"Comma separated list of [attribute=header] pairs mapping SAML IdP response attributes to forwarded request header"`
	NewAuthWebhookUrl       string            `usage:"[URL] of webhook that will get POST'ed when a new authentication is processed"`
	AuthorizeAttribute      string            `usage:"Enables authorization and specifies the [attribute] to check for authorized values"`
	AuthorizeValues         []string          `usage:"If enabled, comma separated list of [values] that must be present in the authorize attribute"`
	CookieMaxAge            time.Duration     `usage:"Specifies the amount of time the authentication token will remain valid" default:"2h"`
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

	httpClient, err := setupHttpClient(cfg.IdpCaPath)
	if err != nil {
		return errors.Wrap(err, "Failed to setup HTTP client")
	}

	samlOpts := samlsp.Options{
		URL:          *rootUrl,
		Key:          keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:  keyPair.Leaf,
		HTTPClient:   httpClient,
		CookieMaxAge: cfg.CookieMaxAge,
		CookieDomain: rootUrl.Hostname(),
	}

	if idpMetadataUrl.Scheme == "file" {
		data, err := ioutil.ReadFile(idpMetadataUrl.Path)
		if err != nil {
			return errors.Wrap(err, "Failed to read IdP metadata file.")
		}
		idpMetadata := &saml.EntityDescriptor{}
		err = xml.Unmarshal(data, idpMetadata)
		if err != nil {
			return errors.Wrap(err, "Failed to unmarshal IdP metadata XML.")
		}
		samlOpts.IDPMetadata = idpMetadata
	} else {
		samlOpts.IDPMetadataURL = idpMetadataUrl
	}

	samlSP, err := samlsp.New(samlOpts)
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

	log.Printf("Serving requests for %s -> %s at %s",
		cfg.BaseUrl, cfg.BackendUrl, cfg.Bind)
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
