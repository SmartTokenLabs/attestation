<?xml version="1.0"?>
<asnx:module xmlns:asnx="urn:ietf:params:xml:ns:asnx"
             name="InformationFramework"
             tagDefault="explicit">

 <namedType name="Name">
  <type>
   <choice>
    <element name="rdnSequence" type="RDNSequence"/>
    <element name="null" type="asnx:NULL"/>
   </choice>
  </type>
 </namedType>

 <namedType name="RDNSequence">
  <type>
   <sequenceOf>
    <element name="item" 
             type="RelativeDistinguishedName"/>
   </sequenceOf>
  </type>
 </namedType>

 <namedType name="RelativeDistinguishedName">
  <type>
   <setOf minSize="1">
    <element name="item"
             type="AttributeTypeAndValue"/>
   </setOf>
  </type>
 </namedType>

 <namedType name="AttributeTypeAndValue">
  <type>
   <sequence>
    <element name="type" type="AttributeType"/>
    <element name="value" type="AttributeValue"/>
   </sequence>
  </type>
 </namedType>

 <namedType name="AttributeType" value="asnx:OBJECT-IDENTIFIER"/>
 <namedType name="AttributeValue">
  <type>
   <anyElement/> <!-- defined by AttributeType -->
  </type>
 </namedType>


</asnx:module>
