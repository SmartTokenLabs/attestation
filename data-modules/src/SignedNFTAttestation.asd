<?xml version="1.0" encoding="UTF-8"?>
<asnx:module name="SignedNFTAttestation" xmlns:asnx="urn:ietf:params:xml:ns:asnx">

    <import name="NFTAttestation"
         schemaLocation="NFTAttestation.asd"/>
    <import name="AlgorithmIdentifier"
         schemaLocation="AuthenticationFramework.asd"/>

    <!-- VERSION 1 since newer versions do not use ASN but instead EIP for the signing -->
    <namedType name="SignedNFTAttestation">
        <type>
            <sequence>
                <element name="nftAttestation" type="NFTAttestation">
                    <annotation>The NFT attestation which is signed</annotation>
                </element>
                </element name="signingAlgorithm" type="AlgorithmIdentifier">
                </element name="signatureValue" type="asnx:BIT-STRING">
            </sequence>
        </type>
    </namedType>
</asnx:module>
