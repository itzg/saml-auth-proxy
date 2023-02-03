#!/bin/bash

# create certificate and key
# IMPORTANT: set this
BASE_FQDN=localhost:8080

KEY_FILE=certs/saml-auth-proxy.key
CERT_FILE=certs/saml-auth-proxy.cert
if [ ! -f "$KEY_FILE" ]; then
  openssl req -x509 -newkey rsa:2048 -keyout $KEY_FILE -out $CERT_FILE -days 365 -nodes -subj "/CN=${BASE_FQDN}"
else
  echo "key and cert already exist, skipping creation"
fi

# start containers
docker-compose up --build -d

# pull down the metadata
curl http://${BASE_FQDN}/saml/metadata > data/metadata.xml

# upload to samlsp.id
echo "Please upload the metadata in data/metadata.xml to https://samltest.id/upload.php"
read useraddedmetadata
echo "You can now visit the site at: http://$BASE_FQDN"

docker-compose logs -f

