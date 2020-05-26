<?xml version="1.0"?>
<asnx:module xmlns:asnx="urn:ietf:params:xml:ns:asnx"
             name="AttestationFramework"
             tagDefault="explicit">

 <import name="AuthenticationFramework"
         schemaLocation="AuthenticationFramework.asd"/>

 <namedType name="SubjectPublicKeyInfo">
  <type>
   <sequence>
    <element name="algorithm" type="AlgorithmIdentifier"/>
    <element name="subjectPublicKey" type="asnx:BIT-STRING"/>
   </sequence>
  </type>
 </namedType>

 <namedType name="SmartContract" type="asnx:INTEGER"/>

</asnx:module>
