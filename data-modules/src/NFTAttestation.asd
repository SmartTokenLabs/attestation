<?xml version="1.0" encoding="UTF-8"?>
<asnx:module name="NFTAttestation" xmlns:asnx="urn:ietf:params:xml:ns:asnx">
    <import name="UriIdAttestation"
         schemaLocation="UriIdAttestation.asd"/>
    <namedType name="NFTAttestation">
        <type>
            <sequence>
                <element name="creator" type="UriIdAttestation">
                    <annotation>The X509v3 certificate that is the attestation identifying the creator/signer</annotation>
                </element>
                <!-- At least one token or "nftDigest" MUST be included -->
                <element name="tokens" type="Tokens">
                    <annotation>The ERC721 tokens to link to</annotation>
                </element>
                <optional>
                    <element name="nftDigest" type="Digest">
                        <annotation>Digest of the content (pic/vid) of the NFT</annotation>
                    </element>
                </optional>
            </sequence>
        </type>
    </namedType>

    <!-- A hash digest -->
    <namedType name="Digest" type="asnx:OCTET-STRING" minSize="32"/>

    <!-- See https://eips.ethereum.org/EIPS/eip-721 for details -->
    <namedType name="Tokens">
        <type>
            <!-- Allowed to be empty if "nftDigest" is included -->
            <sequenceOf>
                <element name="item" type="ERC721"/>
            </sequenceOf>
        </type>
    </namedType>
    <namedType name="ERC721">
        <type>
            <sequence>
                <element name="address" type="Address"/>
                <optional>
                    <element name="tokenIds" type="TokenIds"/>
                </optional>
                <element name="chainID" type="asnx:INTEGER"/>
            </sequence>
        </type>
    </namedType>
    <namedType name="TokenIds">
        <type>
            <choice>
                <sequenceOf>
                    <element name="multipleTokenIds" type="TokenId"/>
                </sequenceOf>
                <element name="singleTokenId" type="TokenId"/>
            </choice>
        </type>
    </namedType>
    <!-- The 256 bit non-negative integer uniquely representing the ERC721 token in question in binary -->
    <namedType name="TokenId" type="asnx:OCTET-STRING" minSize="32" maxSize="32"/>
    <!-- The binary encoding of the 20 bytes representing an Ethereum address -->
    <namedType name="Address" type="asnx:OCTET-STRING" minSize="32" maxSize="20"/>
</asnx:module>
