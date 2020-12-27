# Data modules for attestations

This directory contains various data modules used for cheque, attestations.

The `src` directory has the data module defined on ASN.X (RFC4912). 

The `output/asn` directory has the data module translated to ASN.1. ASN.1 data modules are more human-readable. However, it suffers from ambiguity, modularity and lack of formal definition, therefore not suitable to be used as the input for machine-generated rules and code. For every data module defined in `src`, a translator is used to generate the corresponding output in `output/asn`.

# ASN.X to ASN.1 translator

The translator here is in early experimental use stage. It can't handle all the rules defined in ASN.X (RFC 4912), but it works for the cases we are dealing with so far.

Usage example:

$ saxonb-xslt -s:src/AttestationFramework.asd -xsl:asdxml-to-asn.xsl


