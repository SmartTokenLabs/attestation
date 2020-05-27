<?xml version="1.0"?>
<asnx:module xmlns:asnx="urn:ietf:params:xml:ns:asnx"
             name="InformationFramework"
             tagDefault="explicit">

 <namedType name="Name">
  <type>
   <choice>
    <element name="rdnSequence" type="RDNSequence"/>
   </choice>
  </type>
 </namedType>

 <namedType name="RDNSequence">
  <type>
   <sequenceOf>
    <element name="item" identifier=""
             type="RelativeDistinguishedName"/>
   </sequenceOf>
  </type>
 </namedType>

 <namedType name="RelativeDistinguishedName">
  <type>
   <setOf minSize="1">
    <element name="item" identifier=""
             type="AttributeTypeAndDistinguishedValue"/>
   </setOf>
  </type>
 </namedType>

 <namedType name="AttributeTypeAndDistinguishedValue">
  <type>
   <sequence>
    <element name="type">
     <type>
      <constrained>
       <type>
        <fromClass class="ATTRIBUTE" fieldName="id"/>
       </type>
       <table objectSet="SupportedAttributes"/>
      </constrained>
     </type>
    </element>
    <element name="value">
     <type>
      <constrained>
       <type>
        <fromClass class="ATTRIBUTE" fieldName="Type"/>
       </type>
       <table objectSet="SupportedAttributes">
        <restrictBy>type</restrictBy>
       </table>
      </constrained>
     </type>
    </element>
   </sequence>
  </type>
 </namedType>

 <namedObjectSet name="SupportedAttributes" class="ATTRIBUTE">
  <objectSet>
   <extension/>
  </objectSet>
 </namedObjectSet>

 <namedClass name="ATTRIBUTE">
  <class>
   <typeField name="Type"/>
   <valueField name="id" unique="true"
               type="asnx:OBJECT-IDENTIFIER"/>
  </class>
 </namedClass>

</asnx:module>
