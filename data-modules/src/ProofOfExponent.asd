<?xml version="1.0" encoding="UTF-8"?>
<asnx:module xmlns:asnx="urn:ietf:params:xml:ns:asnx" name="ProofOfExponent">
  <namedType name="Proof">
    <type>
      <sequence>
        <element name="riddle" type="asnx:OCTET-STRING">
          <annotation>The value of which to prove knowledge its discrete logarithm</annotation>
        </element>
        <element name="challengePoint" type="asnx:OCTET-STRING">
          <annotation>The random challenge which is the hash digest of the parameters</annotation>
        </element>
        <element name="responseValue" type="asnx:OCTET-STRING">
          <annotation>The response to the challenge based on the secret exponent</annotation>
        </element>
        <element name="nonce" type="asnx:OCTET-STRING">
          <annotation>The nonce that is linking the proof to a specific usage context</annotation>
        </element>
      </sequence>
    </type>
  </namedType>
  <namedType name="UsageProof">
      <type>
        <sequence>
          <element name="challengePoint" type="asnx:OCTET-STRING">
            <annotation>The random challenge which is the hash digest of the parameters</annotation>
          </element>
          <element name="responseValue" type="asnx:OCTET-STRING">
            <annotation>The response to the challenge based on the secret exponent</annotation>
          </element>
          <element name="nonce" type="asnx:OCTET-STRING">
            <annotation>The nonce that is linking the proof to a specific usage context</annotation>
          </element>
        </sequence>
      </type>
    </namedType>
</asnx:module>
