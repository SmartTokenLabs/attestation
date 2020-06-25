<?xml version="1.0" encoding="UTF-8"?>
<asnx:module name="Cheque" xmlns:asnx="urn:ietf:params:xml:ns:asnx">
    <namedType name="redeem-by-email">
        <type>
            <sequence>
                <element name="amount" type="asnx:Integer"/>
                <element name="riddle" type="asnx:BitStream"/>
            </sequence>
        </type>
    </namedType>
</asnx:module>
