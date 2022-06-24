FROM golang:1.18-alpine3.16 AS builder

WORKDIR /app
COPY . /app
RUN go build


FROM alpine:3.16

RUN apk add --no-cache -U \
  ca-certificates

COPY --from=builder /app/saml-auth-proxy /usr/bin
ENTRYPOINT ["/usr/bin/saml-auth-proxy"]