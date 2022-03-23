<?xml version="1.0" encoding="UTF-8"?>
<asnx:module name="SignedNFTAttestation" xmlns:asnx="urn:ietf:params:xml:ns:asnx">

    <import name="NFTAttestation"
         schemaLocation="NFTAttestation.asd"/>
    <import name="AlgorithmIdentifier"
         schemaLocation="AuthenticationFramework.asd"/>

    <!-- VERSION 1 or 2 since newer versions do not use ASN but instead EIP for the signing -->
    <namedType name="SignedNFTAttestation">
        <type>
            <sequence>
                <element name="nftAttestation" type="NFTAttestation">
                    <annotation>The NFT attestation which is signed</annotation>
                </element>
                <!-- An integer that is 1 or great indicating which signing approach has been used. If not present, version 1 will be assumed
                     Version 1 indicates that everything in nftAttestation is directly signed using an Ethereum personal signature.
                     Version 2 indicates that a compressed signature is used.
                 -->
                <optional>
                  </element name="signingVersion" type="asnx:INTEGER">
                </optional>
                </element name="signingAlgorithm" type="AlgorithmIdentifier">
                </element name="signatureValue" type="asnx:BIT-STRING">
            </sequence>
        </type>
    </namedType>
</asnx:module>
