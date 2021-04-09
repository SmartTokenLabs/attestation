<?xml version="1.0" encoding="UTF-8"?>
<asnx:module name="TransAuthorization" xmlns:asnx="urn:ietf:params:xml:ns:asnx">
    <import name="TokenId"
         schemaLocation="NFTAttestation.asd"/>
    <import name="Address"
         schemaLocation="NFTAttestation.asd"/>
    <import name="Identifier"
         schemaLocation="UriIdAttestation.asd"/>
    <namedType name="TransAuthorization">
        <type>
            <sequence>
                <element name="tokenId" type="TokenId">
                    <annotation>The ERC721 token to link to, the smart contract should look up to find owner based on token Id</annotation>
                </element>
                <element name="tokenContract" type="Address">
                    <annotation>The contract where the token is residing</annotation>
                </element>
                <element name="spender" type="Address">
                    <annotation>The address of contract or individual handling transfer of token</annotation>
                </element>
                <!-- NOT DEFINED YET
                <element name="recipients" type="Recipients">
                    <annotation>The permissible recipient identifiers</annotation>
                </element>
                -->
                <element name="signatureValue" type="asnx:BIT-STRING">
                    <annotation>Algorithm is always ECDSA secp256k1</annotation>
                </element>
            </sequence>
        </type>
    </namedType

    <namedType name="Recipients">
        <type>
            <sequenceOf minSize="1">
                <element name="item" type="Identifier">
                    <annotation>LabeledURI for a permissible identifier</annotation>
                </element>
            </sequenceOf>
        </type>
    </namedType>
</asnx:module>
