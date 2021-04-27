<?xml version="1.0" encoding="UTF-8"?>
<asnx:module name="AttestationRequestWithUsage" xmlns:asnx="urn:ietf:params:xml:ns:asnx">
    <import name="SubjectPublicKeyInfoValue"
         schemaLocation="AttestationFramework.asd"/>
    <import name="Proof"
         schemaLocation="ProofOfExponent.asd"/>
    <import name="IdentifierType"
         schemaLocation="AttestationRequest.asd"/>
    <namedType name="UseAttestation">
        <type>
            <sequence>
                <element name="type" type="IdentifierType">
                    <annotation>The type of identifier used in the attestation</annotation>
                </element>
                <element name="proof" type="Proof">
                    <annotation>A proof containing the user's chosen hiding for his certificate and a proof that this has been correctly constructed.</annotation>
                </element>
                <element name="sessionKey" type="SubjectPublicKeyInfoValue">
                    <annotation>Public verification session key to be used for future authentications</annotation>
                </element>
            </sequence>
        </type>
    </namedType>
</asnx:module>
