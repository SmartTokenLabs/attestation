
<ts:token …>

…
<asnx:module>
 <namedType name="ticket">
  <type>
   <sequence>
    <element name=”numero” type=”asn:Integer”/>
    <element name=”class”>
      <type><enumerated>
        <enumeration name=”normal” number=”0"/>
        <enumeration name=”gift” number=”1"/>
        <enumeration name=”VIP” number=”2"/>
      </enumerated></type>
    </element>
    <element name=”start” type=”asn:UTCTime”/>
   </sequence>
  </type>
 </namedType>
</asn:module>
…

