<?xml version="1.0"?>
<asnx:module xmlns:asnx="urn:ietf:params:xml:ns:asnx"
             name="AuthenticationFramework"
             tagDefault="explicit">

 <namedType name="AlgorithmIdentifier">
  <type>
   <sequence>
    <element name="algorithm">
     <type>
      <fromClass class="ALGORITHM" fieldName="id"/>
     </type>
    </element>
    <optional>
     <element name="parameters">
      <type>
       <fromClass class="ALGORITHM" fieldName="Type"/>
      </type>
     </element>
    </optional>
   </sequence>
  </type>
 </namedType>

 <namedClass name="ALGORITHM" class="ASN-TYPE-IDENTIFIER"/>

 <namedType name="Version">
  <type>
   <namedNumberList>
    <namedNumber name="v1" number="0"/>
    <namedNumber name="v2" number="1"/>
    <namedNumber name="v3" number="2"/>
   </namedNumberList>
  </type>
 </namedType>

 <namedType name="CertificateSerialNumber" type="asnx:INTEGER"/>

 <namedType name="Validity">
  <type>
   <sequence>
    <element name="notBefore" type="Time"/>
    <element name="notAfter" type="Time"/>
   </sequence>
  </type>
 </namedType>

 <namedType name="SubjectPublicKeyInfo">
  <type>
   <sequence>
    <element name="algorithm" type="AlgorithmIdentifier"/>
    <element name="subjectPublicKey" type="asnx:BIT-STRING"/>
   </sequence>
  </type>
 </namedType>

 <namedType name="Time">
  <type>
   <choice>
    <element name="utcTime" type="asnx:UTCTime"/>
    <element name="generalizedTime" type="asnx:GeneralizedTime"/>
   </choice>
  </type>
 </namedType>

 <namedType name="Extensions">
  <type>
   <sequenceOf>
    <element name="item" identifier="" type="Extension"/>
   </sequenceOf>
  </type>
 </namedType>

 <namedType name="Extension">
  <type>
   <sequence>
    <element name="extnId">
     <type>
      <fromClass class="EXTENSION" fieldName="id"/>
     </type>
    </element>
    <optional>
     <element name="critical" type="asnx:BOOLEAN"/>
     <default literalValue="false"/>
    </optional>
    <element name="extnValue" type="asnx:OCTET-STRING"/>
   </sequence>
  </type>
 </namedType>

 <namedClass name="EXTENSION">
  <class>
   <valueField name="id" unique="true"
               type="asnx:OBJECT-IDENTIFIER"/>
   <optional>
    <valueField name="critical" type="asnx:BOOLEAN"/>
    <default literalValue="false"/>
   </optional>
   <typeField name="ExtnType"/>
  </class>
 </namedClass>

</asnx:module>
