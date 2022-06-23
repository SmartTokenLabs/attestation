<?xml version="1.0" encoding="UTF-8"?>
<asnx:module name="SignedEthereumKeyLinkingAttestation" xmlns:asnx="urn:ietf:params:xml:ns:asnx">

    <import name="Address"
         schemaLocation="NFTAttestation.asd"/>
    <import name="AlgorithmIdentifier"
         schemaLocation="AuthenticationFramework.asd"/>
    <import name="SignedNFTOwnershipAttestation"
         schemaLocation="SignedNFTOwnershipAttestation.asd"/>
    <import name="Validity"
         schemaLocation="SignedNFTOwnershipAttestation.asd"/>

    <namedType name="EthereumKeyLinkingAttestation">
        <type>
            <sequence>
                <element name="subjectEthereumAddress" type="Address"/>
                <element name="signedNFTOwnershipAttestation" type="SignedNFTOwnershipAttestation"/>
                <element name="validity" type="Validity"/>
                <optional>
                    <element name="context" type="asnx:OCTET-STRING"/>
                </optional>
            </sequence>
        </type>
    </namedType>

    <namedType name="SignedEthereumKeyLinkingAttestation">
        <type>
            <sequence>
                <element name="ethereumKeyLinkingAttestation" type="EthereumKeyLinkingAttestation"/>
                <element name="signingAlgorithm" type="AlgorithmIdentifier"/>
                <element name="signatureValue" type="asnx:BIT-STRING"/>
            </sequence>
        </type>
    </namedType>
</asnx:module>
