<?xml version="1.0" encoding="UTF-8"?>
<asnx:module name="Cheque" xmlns:asnx="urn:ietf:params:xml:ns:asnx">
    <namedType name="Cheque">
        <type>
            <sequence>
                <element name="amount" type="asnx:INTEGER"/>
                <element name="riddle" type="asnx:OCTET-STRING">
                    <annotation>The elliptic curve point that is the riddle</annotation>
                </element>
                <element name="publicKey" type="asnx:BIT-STRING"/>
                <element name="signatureValue" type="asnx:BIT-STRING">
                    <annotation>Algorithm is always ECDSA secp256k1</annotation>
                </element>
            </sequence>
        </type>
    </namedType>
</asnx:module>
