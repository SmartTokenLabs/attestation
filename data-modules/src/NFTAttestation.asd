<?xml version="1.0" encoding="UTF-8"?>
<asnx:module name="NFTAttestation" xmlns:asnx="urn:ietf:params:xml:ns:asnx">
    <import name="UriIdAttestation"
         schemaLocation="UriIdAttestation.asd"/>
    <namedType name="NFTAttestation">
        <type>
            <sequence>
                <element name="tokens" type="Tokens">
                    <annotation>The ERC721 tokens to link to</annotation>
                </element>
                <optional>
                    <element name="autograph" type="Digest">
                        <annotation>Keccak digest of the content (pic/vid) of the NFT</annotation>
                    </element>
                </optional>
                <element name="creator" type="UriIdAttestation">
                    <annotation>The X509v3 certificate that is the attestation identifying the creator/signer</annotation>
                </element>
                <element name="signatureValue" type="asnx:BIT-STRING">
                    <annotation>Algorithm is always ECDSA secp256k1</annotation>
                </element>
            </sequence>
        </type>
    </namedType>

    <!-- A 256 bit Keccak hash digest -->
    <namedType name="Digest" type="asnx:OCTET-STRING" minSize="32" maxSize="32"/>

    <!-- See https://eips.ethereum.org/EIPS/eip-721 for details -->
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
    <!-- The 256 bit non-negative integer uniquely representing the ERC721 token in question in binary -->
    <namedType name="TokenId" type="asnx:INTEGER"/>
    <!-- The binary encoding of the 20 bytes representing an Ethereum address -->
    <namedType name="Address" type="asnx:OCTET-STRING" minSize="32" maxSize="20"/>
</asnx:module>
