<?xml version="1.0" encoding="UTF-8"?>
<asnx:module xmlns:asnx="urn:ietf:params:xml:ns:asnx"
             name="UriIdAttestation"
             tagDefault="explicit">

 <import name="AlgorithmIdentifier"
         schemaLocation="AuthenticationFramework.asd"/>
 <import name="CertificateSerialNumber"
         schemaLocation="AuthenticationFramework.asd"/>
 <import name="Extensions"
         schemaLocation="AuthenticationFramework.asd"/>
 <import name="Name"
         schemaLocation="InformationFramework.asd"/>

 <namedType name="UriIdAttestation">
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
       <element name="subject" type="Subject"/>
       <element name="subjectPublicKeyInfo"
                 type="SubjectPublicKeyInfo"/>
       <optional>
        <element name="extensions">
         <type>
          <tagged number="3" tagging="explicit" type="Extensions"/>
         </type>
        </element>
       </optional>
      </sequence>
     </type>
    </element>
    <element name="signatureAlgorithm" type="AlgorithmIdentifier"/>
    <element name="signatureValue" type="asnx:BIT-STRING"/>
   </sequence>
  </type>
 </namedType>

 <namedType name="Version" type="asnx:INTEGER" literalValue="19"/>

 <namedType name="Validity">
  <type>
   <sequence>
    <element name="notBefore" type="asnx:GeneralizedTime"/>
    <element name="notAfter" type="asnx:GeneralizedTime" literalValue="99991231235959Z"/>
   </sequence>
  </type>
 </namedType>

 <namedType name="Subject">
  <type>
   <sequence>
    <element name="identifier" type="Identifier"/>
   </sequence>
  </type>
 </namedType>
 <namedType name="Identifier">
  <type>
   <set>
    <element name="identifierTypeAndValue" type="IdentifierTypeAndValue"/>
   </set>
  </type>
 </namedType>
 <namedType name="IdentifierTypeAndValue">
  <type>
   <sequence>
    <!-- MUST be labeledURI  -->
    <element name="type" type="asnx:OBJECT-IDENTIFIER" literalValue="1.3.6.1.4.1.250.1.57"/>
    <!-- MUST be an URI, optionally followed by a space character and then a label -->
    <element name="value" type="asnx:UniversalString"/>
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

</asnx:module>
