<?xml version="1.0" encoding="UTF-8" ?>
<xsl:transform version="2.0"
							 xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
							 xmlns:asnx="urn:ietf:params:xml:ns:asnx"
							 exclude-result-prefixes="xsl asnx">

	<xsl:output method="text" encoding="UTF-8" indent="yes"/>
	<xsl:strip-space elements="*"/>
	
	<xsl:variable name="vSpaces" select="'                                             '"/>
	
	<xsl:template match="@*|node()">
		<xsl:apply-templates select="@*|node()"/>
	</xsl:template>
	
	<xsl:template match="/asnx:module">
		<xsl:text>import {
  BitString,
  compareSchema,
  Integer,
  OctetString,
  Sequence,
  fromBER,
  ObjectIdentifier
} from "asn1js";
import { getParametersValue, clearProps, bufferToHexCodes } from "pvutils";
		</xsl:text>
		<!-- FIXME: handle other imports -->
		<xsl:apply-templates select="namedType[not(@name = current()//*/@type)]"/>

	</xsl:template>
	<xsl:template match="namedType[not(@name = /asnx:module//*/@type)]">
export class <xsl:value-of select="@name"/> {
	constructor(source = {}) {
    if (typeof(source) == "string") {

      const ticketEncoded = (source.startsWith("https://")) ?
          (new URL(source)).searchParams.get('ticket') : source;
      
      let base64str = ticketEncoded
          .split('_').join('+')
          .split('-').join('/')
          .split('.').join('=');

      // source = Uint8Array.from(Buffer.from(base64str, 'base64')).buffer;
      if (typeof Buffer !== 'undefined') {
        source = Uint8Array.from(Buffer.from(base64str, 'base64')).buffer;
      } else {
        source = Uint8Array.from(atob(base64str), c => c.charCodeAt(0)).buffer;
      }
      
    }
    if (source instanceof ArrayBuffer) {
      const asn1 = fromBER(source);
      this.fromSchema(asn1.result);
    } else {
	<xsl:for-each select="type/sequence/*">
		<xsl:call-template name="default-constructor-set-obj"/>	
	</xsl:for-each>	
      
    }
  }		
}
	</xsl:template>
	<xsl:template name="default-constructor-set-obj">
		<xsl:variable name="isOptional" select="self::optional"/>
		<xsl:if test="$isOptional">
			if(source.publicKeyInfo){
		</xsl:if>
		<xsl:choose>
			<xsl:when test="starts-with(@type, 'asnx:')">
			this.<xsl:value-of select="@name"/> = getParametersValue(source, "<xsl:value-of select="@name"/>");	
			</xsl:when>
			<xsl:when test="self::optional">
				<xsl:for-each select="element">
					<xsl:call-template name="default-constructor-set-obj"/>	
				</xsl:for-each>
			</xsl:when>
			<xsl:otherwise>
				this.<xsl:value-of select="@name"/> = new <xsl:value-of select="@type"/>(source.<xsl:value-of select="@name"/>);
			</xsl:otherwise>
		</xsl:choose>
		<xsl:if test="$isOptional">
			}
		</xsl:if>
	</xsl:template>
	
</xsl:transform>
