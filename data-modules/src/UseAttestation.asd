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
                <element name="proof" type="UsageProof">
                    <annotation>Schnorr proof of knowledge based on the commitment in the attestation and signed Devcon Ticket</annotation>
                </element>
               <element name="nonce" type="asnx:OCTET-STRING">
                    <annotation>The nonce used to link this proof to a specific, single usage context</annotation>
                </element>
            </sequence>
        </type>
    </namedType>
</asnx:module>
