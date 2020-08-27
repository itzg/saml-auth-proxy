FROM golang:1.15.0alpine3.12 AS builder

WORKDIR /app
COPY . /app
RUN go build


FROM alpine:3.9

RUN apk add --no-cache -U \
  ca-certificates

COPY --from=builder /app/saml-auth-proxy /usr/bin
ENTRYPOINT ["/usr/bin/saml-auth-proxy"]