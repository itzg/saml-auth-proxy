FROM golang:1.26.5-alpine AS builder

WORKDIR /app
COPY . /app
RUN go build


FROM alpine

RUN apk add --no-cache -U \
  ca-certificates

COPY --from=builder /app/saml-auth-proxy /usr/bin
ENTRYPOINT ["/usr/bin/saml-auth-proxy"]