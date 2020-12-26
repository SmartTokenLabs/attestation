<?xml version="1.0" encoding="UTF-8"?>
<asnx:module name="ReferenceIdentity">
    <namedType name="ReferenceIdentity">
        <type>
            <sequence>
                <element name="identity" type="PrintableString">
                    <annotation>The identity to be validated. Either an email address or a phone number</annotation>
                </element>
                <element name="salt" type="asnx:OCTET-STRING">
                    <annotation>Salt used in constructing the cryptographically hidden identifier</annotation>
                </element>
                <element name="type" version="IdentifierType">
                    <annotation>Integer describing the type of identifier.</annotation>
                </element>
                <element name="proof" type="Schnorr">
                    <annotation>The Schnorr proof that the user know the key used to construct the identifier</annotation>
                </element>
            </sequence>
        </type>
    </namedType>

    <namedType name="Schnorr">
        <type>
            <sequence>
                <element name="generator" type="asnx:OCTET-STRING">
                    <annotation>The generator</annotation>
                <element name="V" type="asnx:OCTET-STRING">
                    <annotation>The random verifier value</annotation>
                </element>
                <element name="challenge" type="asnx:OCTET-STRING">
                    <annotation>The random challenge which is the hash digest of the parameters</annotation>
                </element>
                <element name="response" type="asnx:OCTET-STRING">
                    <annotation>The response to the challenge based on the secret exponent</annotation>
                </element>
            </sequence>
        </type>
    </namedType>
</asnx:module>