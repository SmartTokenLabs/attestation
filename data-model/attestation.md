# Attestation for Cheque

## Outline

### Bob's Attestation
Bob starts by constructing a certificate signing request with the `common name` in  `subject` being Bob's Ethereum address. 
The IdentifierAttestation then uses AnonymousIdentity as dataObject. 
Bob then constructs a new ECDSA secp256k1 key pair and let `identifier` be HMAC_salt(`identity`)^sk for the new secret key he just constructed.
The `identifier` is thus a curve point described as an octet string, as described in [Sec1](https://www.secg.org/sec1-v2.pdf).

An IdentifierAttestation is achieved by sending a Certificate Signing Request as per RFC 2986 and a ReferenceIdentity. The CA then verifies the request and that Bob has control over the email of phone as specified and the ZK proof that Bob knows sk s.t. `identifier` in `AnonymousIdentity` is HMAC_salt(`identity`)^sk. This proof is also based on the ECDSA secp256k1 curve and encoding of points using octet strings.

The CA constructs an Attestation with `AnonymousIdentity` as `dataObject` if the checks are ok. 


## Compiling
Convert asnx files to asd:
`java -jar saxon-he-10.1.jar -s:../blockchain-attestation/data-model/IdentifierAttestation.asd -xsl:../blockchain-attestation/xto1/asdxml-to-asn.xsl >> ../blockchain-attestation/data-model/IdentifierAttestation.asn`
Build the java files
`../../../bin/asn1c  IdentifierAttestation.asn -ber -java -print -pkgname sample_ber.IdentifierAttestation`


Create keys
`openssl ecparam -name secp256k1 -genkey -param_enc explicit -out private-key.pem`
Create CSR
`openssl req -new -sha256 -key private-key.pem -out csr.csr`
Sign
`openssl req -x509 -sha256 -days 365 -key private-key.pem -in csr.csr -out certificate.pem`