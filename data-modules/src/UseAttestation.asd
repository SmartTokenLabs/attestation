<?xml version="1.0" encoding="UTF-8"?>
<asnx:module name="UseAttestation" xmlns:asnx="urn:ietf:params:xml:ns:asnx">
    <import name="MyAttestation"
         schemaLocation="AttestationFramework.asd"/>
    <import name="Proof"
         schemaLocation="ProofOfExponent.asd"/>
    <namedType name="UseAttestation">
        <type>
            <sequence>
                <element name="attestation" type="MyAttestation">
                    <annotation>The X509v3 certificate that is the attestation to be used</annotation>
                </element>
                <element name="proof" type="Proof">
                    <annotation>Schnorr proof of knowledge based on the commitment in the attestation</annotation>
                </element>
            </sequence>
        </type>
    </namedType>
</asnx:module>
