# ASN.X to ASN.1 translator

This translator can't handle all the rules defined in ASN.X (RFC 4912), but it works for the cases we are dealing with so far.

Usage example usage:

$ saxonb-xslt -s:data-model/AttestationFramework.asd -xsl:xto1/asdxml-to-asn.xsl
