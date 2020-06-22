# Attestation Encoding
22 June 2020

### Abstract
We describe how to construct a TokenScript attestation and how this can be expressed as an URI.  

### Status
v. 0.2
First draft by Tore Frederiksen based on the discussion of Weiwu Zhang at <https://community.tokenscript.org/t/a-uri-schema-for-attestations/303>.
Second draft contains further updates based on discussions on <https://community.tokenscript.org>.


## Introduction
This specification builds on top of TokenScript as specified and discussed at <https://www.tokenscript.org>, <https://community.tokenscript.org> and <https://github.com/AlphaWallet/TokenScript>.

This specification builds on top of the TokenScript notion of a `dataObject` as discussed at <https://github.com/AlphaWallet/TokenScript/blob/master/doc/articles/data-object.md>. A `dataObject` is a collection of specific values that define a concrete token based on a definition of variable name and types. However, a `dataObject` itself does not contain any instance information or linking to a specific owner or holder; i.e. some public Ethereum address. To achieve this an attestation is needed. 

An attestation is an object constructed by an Ethereum entity (public/private key pair holder) that attests to a specific TokenScript `dataObject` through some auxiliary information. This auxiliary information can for example be a serial number and version of token-type. 
The attestation of the object _may_ be to another specific Ethereum entity or it could be claimable by _any_ Ethereum entity (through some other attestation and a smart contract-specific interpretation).

We note that an attestation is non-transferable, but that transferability can sometimes be implicitly achieved by attesting to another attestation, rather than a token. 

We desire an attestation to be expressed as succinctly as possible to thus allow each attestation to be fully expressed by an URI, insuring easier and more cross-compatible usage. 

## Attestation Design 
### Design motivation
The design of the attestation URI is motivated by succinctness and thus to avoid it including redundant information or be of low entropy. In particular as URLs and URIs are recommended to be less than 2048 ASCII characters. The overall attestation takes close inspiration from the X.509 certificate specification, RFC-5280, but makes several fields optional, adds a few new ones and changes some formats. 

### Design specification
Observe that an attestation is expressed by a JSON object based on the following ASN1 code:
````Asn1
Attestation-Module DEFINITIONS AUTOMATIC TAGS ::= BEGIN
Attestation { DataObject } ::=  SEQUENCE  {
     signedInfo           SignedInfo,
     signatureAlgorithm   AlgorithmIdentifier, -- Defined in Sec. 4.1.1.2 of RFC 5280
     signatureValue       BIT STRING  
}

SignedInfo { DataObject } ::=  SEQUENCE  {
     version         [0]  EXPLICIT Version,
     serialNumber         CertificateSerialNumber,
     signature            AlgorithmIdentifier, -- Defined in Sec. 4.1.1.2 of RFC 5280
     issuer               Name, -- Almost defined as in Sec. 4.1.2.4 of RFC 2459
     validity             Validity, -- Almost defined as in Sec. 4.1.2.5 of RFC 5280
     subject              Name, -- Almost defined as in Sec. 4.1.2.4 of RFC 5280
     subjectPublicKeyInfo SubjectPublicKeyInfo, -- Almost defined as in Sec. 4.1 of RFC 5280
     attestsTo            CHOICE {
         dataObject  [4]      DataObject -- any data object, ticket is an example
         extensions  [3]      EXPLICIT Extensions 
     }
}

SmartContract ::= INTEGER

END
````
We discuss the fields of `SignedInfo` in relation to X.509 as described in RFC 5280. Other fields that are the same as described in X.509 will not be reiterated here and we instead refer to RFC 5280 <https://tools.ietf.org/html/rfc5280>.

### Dropped fields

#### issuerUniqueID and subjectUniqueID
These fields have been removed as they are optional in X.509 and since identification to the issuer is done implicitly based on its public key and since it might not be desired to explicitly identify a subject.


### Change of optionality
We are, for reasons described below, allowing certain fields to be optional. However due to issues with unambiguous encoding and decoding, we don't use the OPTIONAL keyword but instead require these fields, but allow their content to simply be NULL. The fields in question is `issue`, `validity`, `subject` and `subjectPublicKeyInfo`. 

#### validity
`validity` is defined as in RFC 5280, except that it is also allowed to be NULL. This is because the contract may have an internal mechanism by which time the attestation is no longer valid. e.g. an event ticket is invalidated when the event finishes. If the event date is changed, the smart contract is reconfigured without requiring the attestations to be reissued.

#### subject
`subject` is defined as in RFC 5280, except that it is also allowed to be NULL here. This is so since the attestation constructor might not be identifiable; as-in describable by key-value pairs. We note however that the attestation is still uniquely defined by its serial number and the public key used to construct it.

#### subjectPublicKeyInfo
`subjectPublicKeyInfo` is defined as in RFC 5280, except that it also allowed to be NULL here. This is so because an attestation may bind some claims ("facts") to another attestation instead of a public key. 

Consider, for example, a ticket granting attestation. A ticket is granted to anyone who can prove that his email address is `join.smith@gmail.com`. This makes the ticket attestation depend on another X.509 certificate on that email address. In this case, the certificate has the subjectPublicKeyInfo but the attestation doesn't.


### Semantically modified fields

#### version
Let `a` be the of the attestation; expressed as an integer. We assume `a`<16.
Let `b` be the underlying X.509 certificate which the attention is based on. As of writing, this can be either 1, 2 or 3. We assume `b`<16.

The `version` value of `Attestation` is then defined to be the result of the arithmetic computation (`a`-1)\*16+`b`-1. For example consider that `Attestation` is at version 5 and it is based on X.509 v. 2. Thus `a`=5 and `b`=2 and `version`=65 since (5-1)\*16+2-2=65.

#### issuer
`issuer` is a sequence of relative distinguished names, in particular this includes the string field `Common Name`. For attestations this will be _mandatory_ and not contain a common name, but instead contain information about the public key used to sign the attestation.  If the `signatureAlgorithm` has OID 1.2.840.10045.4.3.2, then this field will contain the Ethereum address. That is, the string "0x" followed by the 20 hex characters defining the address. If the `signatureAlgorithm` does not have OID 1.2.840.10045.4.3.2, then the field _must_ contain the bitstring representing the public key (encoded in non-human readable ASCII).

#### subjectPublicKeyInfo
`subjectPublicKeyInfo` contain info about the entity which the attestation is attesting something for; _if_ the field is not NULL. We note it will have the asn.1 format as follows, as specified in RFC 2459:
````Asn1
SubjectPublicKeyInfo  ::=  CHOICE {
    value   SEQUENCE {
                algorithm            AlgorithmIdentifier,
                subjectPublicKey     BIT STRING  
            },
    null    NULL
   }
````
The `algorithm` field may be left out, in which case it is implicitly assumed to be reflect ECDSA using secp256k1 with SHA256 through OID 1.2.840.10045.4.3.2.

### Added fields

#### dataObject
This field defines which underlying `dataObject` the attestation references and works with.

## Encoding
Encoding an attestation consists of first DER-encoding the information defined by the ASN.1 module. The DER-encoding is then base64 encoded, but with certain fields not being encoded and thus instead contain human-readable ASCII information. 
We compress the encoding by excluding any redundant/recoverable information. This means the public key parameters are excluded and secp256k1 with SHA-256 is assumed by default. 

Besides the encoding of the concrete attestation, the address of the contract at which the attestation will be used must also be included. The address, in its hex form is prepended to the DER-base64 encoding of the compressed attestation using the exclamation point, !, as separator. 

Since we want to use this as an URI/URL we must avoid certain characters with different meaning in URLs which are allowed in base64 encoding. Concretely this means that the addition sign, +, is replaced with the minus sign, -, and that the forward slash, /, is replaced with the underscore, \_, and that the equality sign (used in the end of a base64 encoding) is replaced with the multiplication sign, \*. 

Finally, if ECDSA with SHA256 is used for signing, then we would like the Ethereum public key fingerprint of the signing key to be human recognizable and thus we are mindful of keeping this as a hex encoding. In the same manner we also desire the `dataObject` to be human readable and thus keep this in its ASCII encoding. 

With this in mind we can formalize the steps needed for both encoding and decoding.

### Encoding steps
Encoding takes as argument the address of a smart contract which the attestation should be encoded towards. 
The encoding then proceeds as follows:

1. `signatureAlgorithm` is defined in Sec. 4.1.1.2 of RFC 5280. If the algorithm has OID 1.2.840.10045.4.3.2 (ECDSA with SHA256), then remove `signatureAlgorithm`. Curve choice is not possible under OID 1.2.840.10045.4.3.2 and will be assumed to be secp256k1. Similarly for the optional field `algorithm` in `SubjectPublicKeyInfo`.

2. `signature` is defined in Sec. 4.1.2.3 of RFC 5280. It _must_ contain the same value as `signatureAlgortihm` and is thus always removed.

3. The remaining structure is DER encoded. 

4. The DER encoding is then base64 encoded, with the following exceptions:
* The content of `dataObject` is decoded back into its human readable ASCII representation. It is furthermore moved to the beginning of the encoding (i.e. before the base64 encoding starts) and appended an exclamation point, !. 
* If the `signatureAlgorithm` has OID 1.2.840.10045.4.3.2 then the data in the `Common Name` field within the `Name` structure of the `issuer` field is decoded back into ASCII (which implicitly is actually a hex encoding, and thus human readable). It is  appended an exclamation point, !, and then moved to be right after the exclamation point ending the `dataObject` encoding. Thus the format of the encoding is now:
`<dataObject>!0x<fingerprint>!<base64 of DER encoding>`

5. URL sensitive characters of the ASCII representation are escaped using the URL percent encoding approach as specified in RFC 3986 section 2.1.

6. The address of the smart contract which the attestation is being linked to is appended with an exclamation point, !. Finally the address and exclamation point is prepended to the encoding of the attestation.

7. URL sensitive characters of the encoding (specifically the base64 encoded part) are substituted according to the following rules:
* Addition sign, +, is replaced with the minus sign, -.
* Forward slash, /, is replaced with the underscore, \_.
* Equality, =, is replaced with the multiplication sign, \*.

That is, an attestation will look something like the following when the smart contract address is assumed to be 0x34288B5B65D616B746AE, the fingerprint of the public is 0xAB89BBEF99736629DC23, the `dataObject` has the following ASN.1 form:
````Asn1
"dataObject":{
    "match":1,
    "class":"lounge/lobby",
    "admission":1
}
````
0x34288B5B65D616B746AE!match=1;class=lounge%2Flobby;admission=1;0xAB89BBEF99736629DC23!CICyyZb8QcHv0k0bDUV3T0W_EVGGMWOwKD_RIpnbFT_cTAiBsZiTXYqH870YYKE6tjwhnis-BbE8hCNfFlTmrRaCM-gg\*\*


### Decoding steps
The decoding proceeds like the encoding steps, but in the reverse order thus yielding and ASN.1 attestation and smart contract address. 

### Signing and Verification
The signing will happen on the full decoded ASN.1. Thus it will implicitly include the public key (fingerprint) through `Common Name`, but exclude the smart contract address the current encoding is desired to be used for.

Verification of the signature on an attestation is done as follows:
1. Decode the URI into its ASN.1 format and smart contract address.
2. If a non-ECDSA public key was used, then it is decoded based on its OID from `signatureAlgorithm` using the data in `Common Name`, and the signature on the ASN.1 attestation (but not the smart contract address) is verified against this key.
3. If an ECDSA public key was used then let (r, s) be the values defining the signature and proceed as follows:
* Let Y be the positive square root of r^3+7. I.e. Y=abs(sqrt (r^3+7)) and define the curve points P=(r,Y) and P'=(r,-Y).
* Compute the public key Q=r^(-1)(s\*P-H(m)\*G) and Q'=r^(-1)(s\*P'-H(m)\*G) where H(m) is the hash digest of the message signed (i.e. the decoded attestation) interpreted as a positive integer and G is the base point of secp256k1, i.e. 
(In hex) G=04 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8.
(In decimal) G=60007469361611451595808076307103981948066675035911483428688400614800034609601690612527903279981446538331562636035761922566837056280671244382574348564747448. 
* Verify that either Q or Q' has the same fingerprint as stored in `Common Name` in the `issuer` field. That is, that the last 20 bytes of Keccak-256(Q), interpreted as hex, is the equal to the value in `Common Name` after `0x`.

NOTE: There is a negligible chance (less than 2^(-128)) that it is not possible to restore the public key. This is so small that we don't consider it, however, in case of a malicious signer it is possible to force this event to happen. Still, this will only result in the failure of verification and thus we do not consider this case a problem.