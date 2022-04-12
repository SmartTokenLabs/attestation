#!/bin/bash
openssl ecparam -name secp256k1 -genkey -noout -out key.pem
openssl ec -in key.pem -pubout -out public.pem