package server

import "time"

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
	AttributeHeaderWildcard string            `usage:"Maps all SAML attributes with this option as a prefix"`
	NewAuthWebhookUrl       string            `usage:"[URL] of webhook that will get POST'ed when a new authentication is processed"`
	AuthorizeAttribute      string            `usage:"Enables authorization and specifies the [attribute] to check for authorized values"`
	AuthorizeValues         []string          `usage:"If enabled, comma separated list of [values] that must be present in the authorize attribute"`
	CookieName              string            `usage:"Name of the cookie that tracks session token" default:"token"`
	CookieMaxAge            time.Duration     `usage:"Specifies the amount of time the authentication token will remain valid" default:"2h"`
	CookieDomain            string            `usage:"Overrides the domain set on the session cookie. By default the BaseUrl host is used."`
	AllowIdpInitiated       bool              `usage:"If set, allows for IdP initiated authentication flow"`
	AuthVerify              bool              `usage:"Enables verify path endpoint for forward auth and trusts X-Forwarded headers"`
	AuthVerifyPath          string            `default:"/_verify" usage:"Path under BaseUrl that will respond with a 200 when authenticated"`
	Debug                   bool              `usage:"Enable debug logs"`
	StaticRelayState        string            `usage:"A fixed RelayState value, such as a short URL. Will be trimmed to 80 characters to conform with SAML. The default generates random bytes that are Base64 encoded."`
	InitiateSessionPath     string            `usage:"If set, initiates a SAML authentication flow only when a user visits this path. This will allow anonymous users to access to the backend."`
}
