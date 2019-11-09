#!/bin/bash

#
# The public_root_certs file is made up of a number of root certificates in der format concatenated together.
#
# Root certs sourced from Ubuntu 18.04 LTS /usr/share/ca-certificates/mozilla/
#
# Version must be 3
# ls *.crt | xargs -n 1 openssl x509 -inform pem -text -in | grep "Version"
#
# Public Key Algorithm must be rsaEncryption (2048-bit or 4096-bit)
# ls *.crt | xargs -n 1 openssl x509 -inform pem -text -in | grep "Public Key Algorithm"
# ls *.crt | xargs -n 1 openssl x509 -inform pem -text -in | grep "Public-Key"
#
# Subject key identifier must be 20 bytes (drop "Sonera_Class_2_Root_CA.crt" which has an 8-byte identifier) 
#

rm -f public_root_certs
ls *.crt | xargs -n 1 openssl x509 -outform der -in >>public_root_certs
