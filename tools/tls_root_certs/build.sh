#!/bin/bash

#
# The public_root_certs file is made up of a number of root certificates in der format concatenated together.
#
# Signature Algorithm must be sha256WithRSAEncryption, sha384WithRSAEncryption, or sha512WithRSAEncryption.
# Public Key Algorithm must be rsaEncryption (2048-bit or 4096-bit)
#
# Root certs sourced from Ubuntu 18.04 LTS /usr/share/ca-certificates/mozilla/
#

rm -f public_root_certs
ls *.crt | xargs -n 1 openssl x509 -outform der -in >>public_root_certs
