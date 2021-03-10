<?xml version="1.0" encoding="UTF-8"?>
<asnx:module name="UseAttestation" xmlns:asnx="urn:ietf:params:xml:ns:asnx">
    <import name="MyAttestation"
         schemaLocation="AttestationFramework.asd"/>
    <import name="SubjectPublicKeyInfoValue"
         schemaLocation="AttestationFramework.asd"/>
    <import name="Proof"
         schemaLocation="ProofOfExponent.asd"/>
    <import name="IdentifierType"
         schemaLocation="AttestationRequest.asd"/>
    <namedType name="UseAttestation">
        <type>
            <sequence>
                <element name="attestation" type="MyAttestation">
                    <annotation>The X509v3 certificate that is the attestation to be used</annotation>
                </element>
                <element name="type" type="IdentifierType">
                    <annotation>The type of identifier used in the attestation</annotation>
                </element>
                <element name="proof" type="Proof">
                    <annotation>Schnorr proof of knowledge based on the commitment in the attestation</annotation>
                </element>
                <element name="sessionKey" type="SubjectPublicKeyInfoValue">
                    <annotation>Public verification session key to be used for future authentications</annotation>
                </element>
            </sequence>
        </type>
    </namedType>
</asnx:module>
