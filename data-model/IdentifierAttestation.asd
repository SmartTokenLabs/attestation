<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<ts:attestation xmlns:ts="http://tokenscript.org/2020/06/tokenscript"
          xmlns:ethereum="urn:ethereum:constantinople"
          xmlns:xhtml="http://www.w3.org/1999/xhtml"
          xmlns:asnx="urn:ietf:params:xml:ns:asnx"
          xmlns:xml="http://www.w3.org/XML/1998/namespace"
          xsi:schemaLocation="http://tokenscript.org/2020/06/tokenscript http://tokenscript.org/2020/06/tokenscript.xsd"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          custodian="false"
>
    <asnx:module name="AnonymouseIdentity">
        <namedType name="AnonymousIdentity">
            <type>
                <sequence>
                    <element name="identifier" type="asnx:OCTET-STRING">
                        <annotation>Cryptographically hidden
                        identifiers like email address or mobile phone
                        number.</annotation>
                    </element>
                    <element name="type">
                        <type>
                            <enumerated>
                                <enumeration name="email" number="0"/>
                                <enumeration name="mobile" number="1"/>
                            </enumerated>
                        </type>
                    </element>
                </sequence>
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
    <ts:label>
        <ts:string>Personal Identifier attestation</ts:string>
    </ts:label>
    <card type="action" name="renew">
      …
    </card>
</ts:attestation>
