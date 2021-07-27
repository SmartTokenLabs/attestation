<?xml version="1.0" encoding="UTF-8"?>
<asnx:module name="UseDevconTicket" xmlns:asnx="urn:ietf:params:xml:ns:asnx">
    <import name="MyAttestation"
         schemaLocation="AttestationFramework.asd"/>
    <import name="SignedDevconTicket"
         schemaLocation="SignedDevconTicket.asd"/>
    <import name="UsageProof"
         schemaLocation="ProofOfExponent.asd"/>
    <namedType name="UseDevconTicket">
        <type>
            <sequence>
                <element name="signedDevconTicket" type="SignedDevconTicket">
                    <annotation>The actual, signed, ticket object</annotation>
                </element>
                <element name="attestation" type="MyAttestation">
                    <annotation>The X509v3 certificate that is the attestation to be used for redeeming</annotation>
                </element>
                <element name="proof" type="UsageProof">
                    <annotation>Schnorr proof of knowledge based on the commitment in the attestation and signed Devcon Ticket</annotation>
                </element>
            </sequence>
        </type>
    </namedType>
</asnx:module>
