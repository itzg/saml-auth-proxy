[![CircleCI](https://circleci.com/gh/itzg/saml-auth-proxy.svg?style=svg)](https://circleci.com/gh/itzg/saml-auth-proxy)
[![](https://img.shields.io/github/release/itzg/saml-auth-proxy.svg?style=flat)](https://github.com/itzg/saml-auth-proxy/releases/latest)
[![](https://img.shields.io/docker/pulls/itzg/saml-auth-proxy.svg?style=flat)](https://hub.docker.com/r/itzg/saml-auth-proxy)

Provides a SAML SP authentication proxy for backend web services

## Usage

```text
Usage:
  saml-auth-proxy [flags]

Flags:
      --attribute-header-mappings stringToString   Comma separated list of attribute=header pairs mapping SAML IdP response attributes to forwarded request header [SAML_PROXY_ATTRIBUTE_HEADER_MAPPINGS] (default [])
      --backend-url string                         URL of the backend being proxied [SAML_PROXY_BACKEND_URL]
      --base-url string                            External URL of this proxy [SAML_PROXY_BASE_URL]
      --bind string                                host:port to bind for serving HTTP [SAML_PROXY_BIND] (default ":8080")
  -h, --help                                       help for saml-auth-proxy
      --idp-ca-path string                         Optional path to a CA certificate PEM file for the IdP [SAML_PROXY_IDP_CA_PATH]
      --idp-metadata-url string                    URL of the IdP's metadata XML [SAML_PROXY_IDP_METADATA_URL]
      --name-id-format string                      One of unspecified, transient (default), email, or persistent to use a standard format or give a full URN of the name ID format [SAML_PROXY_NAME_ID_FORMAT]
      --name-id-mapping string                     Name of the request header to convey the SAML nameID/subject [SAML_PROXY_NAME_ID_MAPPING]
      --new-auth-webhook-url string                URL of webhook that will get POST'ed when a new authentication is processed [SAML_PROXY_NEW_AUTH_WEBHOOK_URL]
      --sp-cert-path string                        Path to the X509 public certificate PEM file for this SP [SAML_PROXY_SP_CERT_PATH] (default "saml-auth-proxy.cert")
      --sp-key-path string                         Path to the X509 private key PEM file for this SP [SAML_PROXY_SP_KEY_PATH] (default "saml-auth-proxy.key")
      --version                                    version for saml-auth-proxy
```

The snake-case values, such as `SAML_PROXY_BACKEND_URL`, are the equivalent environment variables
that can be set instead of passing configuration via the command-line.

## Note for AJAX/Fetch Operations

If the web application being protected behind this proxy makes AJAX/Fetch calls, then be sure
to enable "same-origin" access for the credentials of those calls, 
as described [here](https://developer.mozilla.org/en-US/docs/Web/API/Request/credentials).

With that configuration in place, the AJAX/Fetch calls will leverage the same `token` cookie 
provided in response to the first authenticated page retrieval via the proxy.

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
curl localhost:8000/saml/metadata > saml-sp-metadata.xml
```

You can post the content of the `saml-sp-metadata.xml` file at 
[SSOCircle's SP metadata page](https://idp.ssocircle.com/sso/hos/ManageSPMetadata.jsp).

Now you can open your browser and navigate to `http://${BASE_FQDN}:8080`. You will be redirected
via SSOCircle's login page and then be returned with access to Grafana.
