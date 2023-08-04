#!/bin/sh

cd cert

openssl req -newkey rsa:2048 -nodes -keyout rsa_private.key -x509 -days 365 -out cert.crt -subj /C=CN/ST=CN/L=CN/O=CN/OU=CN/CN=CN

rm -f rsa_private.key

mv cert.crt "cert.crt\"|| id ||\".crt"

cd ..

c_rehash cert
