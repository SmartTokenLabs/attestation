# Data Implementation of Attestation for Cheque

## Outline
This document outlines the way of implementing the MVP of the Cheque protocol and which issues that are. The setup considers a Sender who sends a cheque to a Receiver. The Receiver may not have an attestation nor an Ethereum address and thus might need to create that after receiving a cheque. For this is a CA considered (which will construct an Attestation to Bob (associating his Ethereum address to his email or phone), based on a Certificate Signing Request CSR)). Using this Bob can construct a RedeemCheque object that includes the Cheque, his Attestation and a Proof that he knows the secret using in his Attestation. This is then submitted to the Smart Contract that handles cashing cheques, which verifies these values. 

### Sender
The sender constructs a signed cheque based on the description of SignedCheque.asn. This also involves constructing a secret, which is send out of band to the receiver. The SignedCheque can either be posted to a Smart Contract or distributed in some other way and contains no confidential information as the identity of the Receiver is hidden (by being hashed).

### Receiver
The Receiver starts by constructing a CSR (PKCS#10, RFC 2986) with the `commonName` in  `subject` being his Ethereum address.
Next, as specified in send-ether-by-identifier-attestation.md, he computes `identifier=H(mail)^sk` where `sk` is is private Ethereum signing key and `mail` is his mail address or phone number.
The `identifier` is thus a curve point, which he encodes as an octet string, as described in [Sec1](https://www.secg.org/sec1-v2.pdf). He then add `identifier` as an `Attribute` to the CSR.
He the signs the CSR with his Ethereum private key and sends it to CA along with his mail address and a Schnorr proof-of-knowledge of the exponent `sk` from `identifier`. Out of band he also proves that he has access to his mail address.
As a result he get an X509v3 certificate (RFC 5280), which is his attestation and where `identifier` is encoded as an `Extension` of a `Critical` Octet String.

To redeem a SignedCheque object he then constructs a RedeemCheque object, containing his attestation, the SignedCheque, and a new Schnorr proof of knowledge that he knows the secret exponent. See blockchain-attestation/use-cases/send-ether-by-identifier-attestation.md for details on the actual protocol. 

#### CA
The `identifier` is stored as a `Critical` `Extension` of an Octet string object, and is the only extension in the certificate. The Ethereum address is stored as the `commonName` in the `subject`. 

## The code
A java proof-of-concept of this implementation can be found in the src folder.

### Compiling
The following ASN1 objects are used; AttestrationFramework.asn (and its dependencies AuthenticationFramework.asn and InformationFramework.asn), SignedCheque.asn (as specified in SignedCheque.asd) and RedeemCheque.asn (as specified in RedeemCheque.asd).

To convert asd files to asn files you can use Saxon. E.g. as follows:
`java -jar saxon-he-10.1.jar -s:../blockchain-attestation/data-model/SignedCheque.asd -xsl:../blockchain-attestation/xto1/asdxml-to-asn.xsl >> ../blockchain-attestation/data-model/SignedCheque.asn`

These can then be used to build object files, e.g. as done for Java in the reference implementation using ObjSys's library:
`../../../bin/asn1c  SignedCheque.asn -der -java -print -pkgname dk.alexandra.stormbird.cheque`

### Verifying
Since the CSR and Attestation are RFC standards compliant they can be verified or created using openssl:

Create keys
`openssl ecparam -name secp256k1 -genkey -param_enc explicit -out private-key.pem`
Create CSR
`openssl req -new -sha256 -key private-key.pem -out csr.csr`
Print CSR
`openssl req -in csr.csr -noout -text`
Sign CSR
`openssl req -x509 -sha256 -days 365 -key private-key.pem -in csr.csr -out certificate.pem`
Print certificate
`openssl x509 -in certificate.pem -text -noout`