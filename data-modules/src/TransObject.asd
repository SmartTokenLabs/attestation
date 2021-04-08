<?xml version="1.0" encoding="UTF-8"?>
<asnx:module name="UseDevconTicket" xmlns:asnx="urn:ietf:params:xml:ns:asnx">
    <import name="NFTAttestation"
         schemaLocation="NFTAttestation.asd"/>
    <namedType name="TransObject">
        <type>
            <sequence>
                <element name="tokens" type="Tokens">
                    <annotation>The ERC721 tokens to link to</annotation>
                </element>
                <element name="attestation" type="NFTAttestation">
                    <annotation>The X509v3 certificate that is the attestation identifying the signer</annotation>
                </element>
                <element name="signatureValue" type="asnx:BIT-STRING">
                    <annotation>Algorithm is always ECDSA secp256k1</annotation>
                </element>
            </sequence>
        </type>
    </namedType>

    <namedType name="Tokens">
        <type>
            <sequenceOf minSize="1">
                <element name="item" type="ERC721"/>
            </sequenceOf>
        </type>
    </namedType>
    <namedType name="ERC721">
        <type>
            <sequence>
                  <element name="tokenId" type="TokenId"/>
                  <element name="address" type="Address"/>
            </sequence>
        </type>
    </namedType>
    <namedType name="TokenId" type="asnx:OCTET-STRING" minSize="32" maxSize="32"/>
    <namedType name="Address" type="asnx:OCTET-STRING" minSize="32" maxSize="20"/>
</asnx:module>
