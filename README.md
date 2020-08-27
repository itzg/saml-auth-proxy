[![CircleCI](https://circleci.com/gh/itzg/saml-auth-proxy.svg?style=svg)](https://app.circleci.com/pipelines/github/itzg/saml-auth-proxy)
[![](https://img.shields.io/github/release/itzg/saml-auth-proxy.svg?style=flat)](https://github.com/itzg/saml-auth-proxy/releases/latest)
[![](https://img.shields.io/docker/pulls/itzg/saml-auth-proxy.svg?style=flat)](https://hub.docker.com/r/itzg/saml-auth-proxy)

Provides a SAML SP authentication proxy for backend web services

## Usage

```text
  -allow-idp-initiated
        If set, allows for IdP initiated authentication flow (env SAML_PROXY_ALLOW_IDP_INITIATED)
  -attribute-header-mappings attribute=header
        Comma separated list of attribute=header pairs mapping SAML IdP response attributes to forwarded request header (env SAML_PROXY_ATTRIBUTE_HEADER_MAPPINGS)
  -attribute-header-wildcard
        Maps all SAML attributes with this option as a prefix (env SAML_PROXY_ATTRIBUTE_HEADER_WILDCARD)
  -authorize-attribute attribute
        Enables authorization and specifies the attribute to check for authorized values (env SAML_PROXY_AUTHORIZE_ATTRIBUTE)
  -authorize-values values
        If enabled, comma separated list of values that must be present in the authorize attribute (env SAML_PROXY_AUTHORIZE_VALUES)
  -backend-url URL
        URL of the backend being proxied (env SAML_PROXY_BACKEND_URL)
  -base-url URL
        External URL of this proxy (env SAML_PROXY_BASE_URL)
  -bind host:port
        host:port to bind for serving HTTP (env SAML_PROXY_BIND) (default ":8080")
  -cookie-max-age duration
        Specifies the amount of time the authentication token will remain valid (env SAML_PROXY_COOKIE_MAX_AGE) (default 2h0m0s)
  -idp-ca-path path
        Optional path to a CA certificate PEM file for the IdP (env SAML_PROXY_IDP_CA_PATH)
  -idp-metadata-url URL
        URL of the IdP's metadata XML, can be a local file by specifying the file:// scheme (env SAML_PROXY_IDP_METADATA_URL)
  -name-id-format string
        One of unspecified, transient, email, or persistent to use a standard format or give a full URN of the name ID format (env SAML_PROXY_NAME_ID_FORMAT) (default "transient")
  -name-id-mapping header
        Name of the request header to convey the SAML nameID/subject (env SAML_PROXY_NAME_ID_MAPPING)
  -new-auth-webhook-url URL
        URL of webhook that will get POST'ed when a new authentication is processed (env SAML_PROXY_NEW_AUTH_WEBHOOK_URL)
  -sp-cert-path path
        The path to the X509 public certificate PEM file for this SP (env SAML_PROXY_SP_CERT_PATH) (default "saml-auth-proxy.cert")
  -sp-key-path path
        The path to the X509 private key PEM file for this SP (env SAML_PROXY_SP_KEY_PATH) (default "saml-auth-proxy.key")
  -version
        show version and exit
```

The snake-case values, such as `SAML_PROXY_BACKEND_URL`, are the equivalent environment variables that can be set instead of passing configuration via the command-line. 

The command-line argument usage renders with only a single leading dash, but GNU-style double-dashes can be used also, such as `--sp-key-path`.

## Authorization

The proxy has support for not only authenticating users via a SAML IdP, but can also further authorize access by evaluating the attributes included in the SAML response assertion.

The authorization is configured with the combination of `--authorize-attribute` and `--authorize-values`. 

**NOTE** the attribute is case sensitive, so be sure to specify that parameter exactly as it appears in the `Name` attribute of the `<saml:Attribute>` element.

The values are a comma separated list of authorized values and since the assertion attributes can contain more than one value also, the authorization performs an "intersection" matching any one of the expected values with any one of the assertion attribute values. That allows for matching user IDs where the assertion has a single value but you want to allow one or more users to be authorized. It also allows for matching group names where each user may be belong to more than one group and you may want to also authorize any number of groups.

## Note for AJAX/Fetch Operations

If the web application being protected behind this proxy makes AJAX/Fetch calls, then be sure
to enable "same-origin" access for the credentials of those calls, 
as described [here](https://developer.mozilla.org/en-US/docs/Web/API/Request/credentials).

With that configuration in place, the AJAX/Fetch calls will leverage the same `token` cookie 
provided in response to the first authenticated page retrieval via the proxy.

When the user is authorized, the proxied request header `X-Authorized-Using` will be populated with the `attribute=value` that was matched, such as 

```
X-Authorized-Using: UserID=user1
```

## Health Endpoint

The proxy itself provides a health endpoint at `/_health` that can be used to confirm the proxy is healthy/ready independent of the SAML processing. It returns a status code of 200 and a `text/plain` body with "OK".

## Building

With Go 1.11 or newer:

```
go build
```

## Trying it out

The following procedure will enable you to try out the proxy running locally and using
Grafana as a backend to proxy with authentication. It will use [SSOCircle](https://www.ssocircle.com)
as a SAML IdP.

Start the supplied Grafana and Web Debug Server using Docker Compose:

```bash
docker-compose up -d
```

Create a domain name that resolves to 127.0.0.1 and use that as the `BASE_FQDN` in the following
operations;

Generate the SP certificate and key material by running:

```bash
openssl req -x509 -newkey rsa:2048 -keyout saml-auth-proxy.key -out saml-auth-proxy.cert -days 365 -nodes -subj "/CN=${BASE_FQDN}"
```

Start saml-auth-proxy using:

```bash
./saml-auth-proxy \
  --base-url http://${BASE_FQDN}:8080 \
  --backend-url http://locahost:3000 \
  --idp-metadata-url https://idp.ssocircle.com/ \
  --attribute-header-mappings UserID=x-webauth-user
```

Generate your SP's SAML metadata by accessing the built-in metadata endpoint:

```bash
curl localhost:8080/saml/metadata > saml-sp-metadata.xml
```

You can post the content of the `saml-sp-metadata.xml` file at 
[SSOCircle's SP metadata page](https://idp.ssocircle.com/sso/hos/ManageSPMetadata.jsp).

**Note** you will also be selecting the attributes that will be included in the assertion in the SAML authentication response, such as: 
- `FirstName`
- `LastName`
- `EmailAddress`
- `UserID`

To try out authorization you would add the following arguments referencing something like `UserID` and one or more expected SSOCircle user's values:

```
  --authorize-attribute UserID \
  --authorize-values user1,user2
```

Now you can open your browser and navigate to `http://${BASE_FQDN}:8080`. You will be redirected
via SSOCircle's login page and then be returned with access to Grafana.

## Troubleshooting

### ERROR: failed to decrypt response

If the SAML redirect results in a "Forbidden" white-page and the saml-auth-proxy outputs a log like the following, then be sure to double check that the subject/CN of the generated certificate matches the FQDN of the deployed endpoint.

```
ERROR: failed to decrypt response: crypto/rsa: decryption error
```

After correcting the certificate and key, be sure to regenerate the metadata and provide that to the ADFS/SAML IdP owner.
