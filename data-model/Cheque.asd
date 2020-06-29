<?xml version="1.0" encoding="UTF-8"?>
<asnx:module name="Cheque" xmlns:asnx="urn:ietf:params:xml:ns:asnx">
    <namedType name="redeem-by-email">
        <type>
            <sequence>
                <element name="amount" type="asnx:INTEGER"/>
                <!-- Phone number or mail address -->
                <element name="identifier" type="asnx:PrintableString"/>
                <element name="riddle" type="Riddle"/>
            </sequence>
        </type>
    </namedType>

    <namedType name="Riddle">
    	<type>
            <sequence>
                <!-- Encoding of the two large integers representing a curve point -->
                <element name="x" type="asnx:OCTET-STRING"/>
				<element name="y" type="asnx:OCTET-STRING"/>
			</sequence>
		</type>
    </namedType>
</asnx:module>
