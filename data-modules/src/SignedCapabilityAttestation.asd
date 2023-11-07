<?xml version="1.0" encoding="UTF-8"?>
<asnx:module name="SignedCapabilityAttestation" xmlns:asnx="urn:ietf:params:xml:ns:asnx">
    <namedType name="SignedCapabilityAttestation">
        <type>
            <sequence>
                <element name="capabilityAttestation" type="CapabilityAttestation">
                    <annotation>The actual, unsigned, capability attestation</annotation>
                </element>
                <element name="signatureValue" type="asnx:BIT-STRING"/>
            </sequence>
        </type>
    </namedType>
    <namedType name="CapabilityAttestation">
        <type>
            <sequence>
                <element name="uniqueId" type="asnx:INTEGER"/>
                <element name="sourceDomain" type="asnx:UTF8String"/>
                <element name="targetDomain" type="asnx:UTF8String"/>
                <element name="notBefore" type="asnx:INTEGER"/>
                <element name="notAfter" type="asnx:INTEGER"/>
                <element name="capabilities" type="asnx:BIT-STRING"/>
            </sequence>
        </type>
    </namedType>
</asnx:module>
