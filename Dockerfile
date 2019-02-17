FROM scratch
COPY saml-auth-proxy /
ENTRYPOINT ["/saml-auth-proxy"]