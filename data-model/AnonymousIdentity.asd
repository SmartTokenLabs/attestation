<?xml version="1.0" encoding="UTF-8"?>
<asnx:module name="AnonymousIdentity">
    <namedType name="AnonymousIdentity" type="dataObject">
        <type>
            <sequence>
                <element name="identifier" type="asnx:OCTET-STRING">
                    <annotation>Cryptographically hidden
                        identifiers like email address or mobile phone
                        number.</annotation>
                </element>
                <element name="salt" type="asnx:OCTET-STRING">
                    <annotation>Salt used in constructing the cryptographically hidden identifier</annotation>
                </element>
                <element name="type">
                        <type>
                            <tagged number="0" tagging="explicit" type="IdentifierType"/>
                        </type>
                    <annotation>Integer describing the type of identifier.</annotation>
                </element>
            </sequence>
        </type>
    </namedType>

    <namedType name="IdentifierType">
        <type>
            <namedNumberList>
                <namedNumber name="email" number="0"/>
                <namedNumber name="phone" number="1"/>
            </namedNumberList>
        </type>
    </namedType>
</asnx:module>