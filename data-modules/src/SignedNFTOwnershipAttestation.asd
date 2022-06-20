<?xml version="1.0" encoding="UTF-8"?>
<asnx:module name="SignedNFTOwnershipAttestation" xmlns:asnx="urn:ietf:params:xml:ns:asnx">

    <import name="Address"
         schemaLocation="NFTAttestation.asd"/>
    <import name="TokenId"
         schemaLocation="NFTAttestation.asd"/>
    <import name="AlgorithmIdentifier"
         schemaLocation="AuthenticationFramework.asd"/>
    <import name="SubjectPublicKeyInfoValue"
         schemaLocation="AuthenticationFramework.asd"/>

    <namedType name="Validity">
        <type>
            <sequence>
                <element name="notBefore" type="asnx:INTEGER"/>  <!-- time in seconds since epoch -->
                <element name="notAfter" type="asnx:INTEGER"/>  <!-- time in seconds since epoch -->
            </sequence>
        </type>
    </namedType>

    <namedType name="NFTOwnershipAttestation">
        <type>
            <sequence>
                <optional>
                    <element name="context" type="asnx:OCTET-STRING"/>
                </optional>
                <element name="subjectPublicKey" type="SubjectPublicKeyInfoValue"/>
                <element name="contractAddress" type="Address"/>
                <element name="chainId" type="asnx:INTEGER"/>
                <optional>
                    <element name="tokenId" type="TokenId"/>
                </optional>
                <element name="validity" type="Validity"/>
            </sequence>
        </type>
    </namedType>

    <namedType name="SignedNFTOwnershipAttestation">
        <type>
            <sequence>
                <element name="nftOwnershipAttestation" type="NFTOwnershipAttestation"/>
                <element name="signingAlgorithm" type="AlgorithmIdentifier"/>
                <element name="signatureValue" type="asnx:BIT-STRING"/>
            </sequence>
        </type>
    </namedType>
</asnx:module>
