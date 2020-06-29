<?xml version="1.0" encoding="UTF-8"?>
<asnx:module xmlns:asnx="urn:ietf:params:xml:ns:asnx"
             name="AttestationFramework"
             tagDefault="explicit">

 <import name="AuthenticationFramework"
         schemaLocation="AuthenticationFramework.asd"/>

 <import name="InformationFramework"
         schemaLocation="InformationFramework.asd"/>

 <namedType name="MyAttestation">
  <type>
   <sequence>
    <element name="signedInfo">
     <type>
      <sequence>
       <element name="version">
        <type>
         <tagged number="0" tagging="explicit" type="Version"/>
        </type>
       </element>
       <element name="serialNumber" type="CertificateSerialNumber"/>
       <element name="signature" type="AlgorithmIdentifier"/>
       <element name="issuer" type="Name"/>
       <element name="validity" type="Validity"/>
       <element name="subject" type="Name"/>
       <element name="subjectPublicKeyInfo"
                 type="SubjectPublicKeyInfo"/>
       <optional>
        <element name="contract">
         <type>
          <sequenceOf>
           <element name="item" type="SmartContract"/>
          </sequenceOf>
         </type>
        </element>
       </optional>
       <element name="attestsTo">
        <type>
         <choice>
          <element name="dataObject">
           <type>
            <tagged number="0" type="DataObject"/>
           </type>
          </element>
          <element name="extensions">
           <type>
            <tagged number="3" tagging="explicit" type="Extensions"/>
           </type>
          </element>
         </choice>
        </type>
       </element>
      </sequence>
     </type>
    </element>
    <element name="signatureAlgorithm" type="AlgorithmIdentifier"/>
    <element name="signatureValue" type="asnx:BIT-STRING"/>
   </sequence>
  </type>
 </namedType>

 <namedType name="SubjectPublicKeyInfo">
  <type>
   <choice>
    <sequence>
     <element name="algorithm" type="AlgorithmIdentifier"/>
     <element name="subjectPublicKey" type="asnx:BIT-STRING"/>
    </sequence>
    <element name="null" type="asnx:NULL"/>
   </choice>
  </type>
 </namedType>

 <namedType name="SmartContract" type="asnx:INTEGER"/>
</asnx:module>
