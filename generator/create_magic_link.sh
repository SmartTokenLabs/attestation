#!/bin/bash
java -cp ../build/libs/attestation-0.3.17-all.jar org.devcon.ticket.Issuer ./key.pem email@email.com 111 222 333 2>/dev/null > ./magiclink.txt 