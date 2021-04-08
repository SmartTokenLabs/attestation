<?xml version="1.0" encoding="UTF-8"?>
<asnx:module name="TransAuthorization" xmlns:asnx="urn:ietf:params:xml:ns:asnx">
    <import name="ERC721"
         schemaLocation="TransObject.asd"/>
    <import name="Address"
         schemaLocation="TransObject.asd"/>
    <import name="Identifier"
         schemaLocation="NFTAttestation.asd"/>
    <namedType name="TransAuthorization">
        <type>
            <sequence>
                <element name="token" type="ERC721">
                    <annotation>The ERC721 token to link to</annotation>
                </element>
                <element name="contract" type="Address">
                    <annotation>The address of the smart contract handling transmogrify</annotation>
                </element>
                <element name="sender" type="Address">
                    <annotation>The address of the sender</annotation>
                </element>
                <element name="recipients" type="Recipients">
                    <annotation>The permissible recipient identifiers</annotation>
                </element>
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
