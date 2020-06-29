<?xml version="1.0" encoding="UTF-8"?>
<asnx:module name="AnonymouseIdentity">
        <namedType name="AnonymousIdentity">
            <type>
                <sequence>
                    <element name="identifier" type="asnx:OCTET-STRING">
                        <annotation>Cryptographically hidden
                        identifiers like email address or mobile phone
                        number.</annotation>
                    </element>
                    <element name="type" version="Type">
                        <annotation>Integer describing the type of identifier.</annotation>
                    </element>
                    <element name="eth-address" version="asnx:PrintableString">
                        <annotation>The Ethereum address that owns the hidden identifier</annotation>
                    </element>
                </sequence>
            </type>
        </namedType>

        <namedType name="Type">
            <type>
                <namedNumberList>
                    <namedNumber name="email" number="0"/>
                    <namedNumber name="phone" number="1"/>
                </namedNumberList>
            </type>
        </namedType>

        <namedType name="IdentifierAttestationSingingRequest">
            <type>
                <sequence>
                    <!-- needs to be filled in -->
                </sequence>
            </type>
        </namedType>
    </asnx:module>
