FROM alpine:3.9

RUN apk add --no-cache -U \
  ca-certificates

COPY saml-auth-proxy /usr/bin
ENTRYPOINT ["/usr/bin/saml-auth-proxy"]