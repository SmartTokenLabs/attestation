<?xml version="1.0" encoding="UTF-8"?>
<asnx:module name="SignedNFTAttestation" xmlns:asnx="urn:ietf:params:xml:ns:asnx">

    <import name="NFTAttestation"
         schemaLocation="NFTAttestation.asd"/>
    <import name="AlgorithmIdentifier"
         schemaLocation="AuthenticationFramework.asd"/>

    <namedType name="SignedNFTAttestation">
        <type>
            <sequence>
                <element name="nftAttestation" type="NFTAttestation">
                    <annotation>The NFT attestation which is signed</annotation>
                </element>
                <!-- An integer that is 1 or great indicating which signing approach has been used. If not present, version 1 will be assumed -->
                <optional>
                  </element name="signingVersion" type="asnx:INTEGER">
                </optional>
                </element name="signingAlgorithm" type="AlgorithmIdentifier">
                </element name="signatureValue" type="asnx:BIT-STRING">
            </sequence>
        </type>
    </namedType>
</asnx:module>
