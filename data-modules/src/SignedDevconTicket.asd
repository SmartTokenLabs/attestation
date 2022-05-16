<?xml version="1.0" encoding="UTF-8"?>
<asnx:module name="SignedTicket" xmlns:asnx="urn:ietf:params:xml:ns:asnx">
<import name="AlgorithmIdentifier"
         schemaLocation="AuthenticationFramework.asd"/>
    <namedType name="SignedDevconTicket">
        <type>
            <sequence>
                <element name="ticket" type="DevconTicket">
                    <annotation>The actual, unsigned, ticket object</annotation>
                </element>
                <element name="signatureValue" type="asnx:BIT-STRING"/>
            </sequence>
        </type>
    </namedType>
    <namedType name="DevconTicket">
        <type>
            <sequence>
                <element name="devconId" type="asnx:UTF8String"/>
                <element name="ticketId" type="TicketId"/>
                <element name="ticketClass" type="asnx:INTEGER"/>
                <!-- (currently not specified)
                <element name="co2_token" type="asnx:OCTET-STRING"/>
                -->
                <element name="commitment" type="asnx:OCTET-STRING">
                  <annotation>The elliptic curve point that is a commitment to the ticket holder's identifier</annotation>
                </element>
            </sequence>
        </type>
    </namedType>
    <namedType name="TicketId">
      <type>
        <choice>
          <element name="integerId" type="asnx:INTEGER"/>
          <element name="stringId" type="asnx:UTF8String"/>
        </choice>
      </type>
    </namedType>
</asnx:module>
