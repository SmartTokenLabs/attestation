<?xml version="1.0" encoding="UTF-8" ?>
<xsl:transform version="2.0"
							 xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
							 xmlns:asnx="urn:ietf:params:xml:ns:asnx"
							 xmlns:f="f"
							 exclude-result-prefixes="xsl asnx f">

	<xsl:output method="text" encoding="UTF-8" indent="yes"/>
	<xsl:strip-space elements="*"/>
	
	<xsl:variable name="vSpaces" select="'                                             '"/>
	<xsl:param name="delim" select="','" />
	<xsl:param name="quote" select="'&quot;'" />
	<xsl:param name="break" select="'&#xA;'" />
  
  
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
	<!-- FIXME: variable names and URL parameters should be dynamic too -->	
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
    static defaultValues(memberName) {
      switch (memberName) {
		<xsl:for-each select="type/sequence/optional">
		case "<xsl:value-of select="element/@name"/>":
			return new <xsl:value-of select="element/@name"/>();
		</xsl:for-each>	  
        default:
          throw new Error(`Invalid member name for <xsl:value-of select="@name"/> class: ${memberName}`);
      }
    }
	
	<!-- generate function schema -->
	<xsl:call-template name="schema"/>
	
  }		
}
	</xsl:template>
	<xsl:template name="default-constructor-set-obj">
		<xsl:variable name="className" select="ancestor::namedType[1]/@name"/>
		<xsl:variable name="isOptional" select="self::optional"/>
		<xsl:variable name="defaultValue" select="if(parent::optional) then concat(', ', $className, '.defaultValues(', $quote, @name, $quote, ')') else /.."/>
		<xsl:if test="$isOptional">
			if(source.<xsl:value-of select="element/@name"/>){
		</xsl:if>
		<xsl:choose>
			<xsl:when test="starts-with(@type, 'asnx:') or parent::optional">
				this.<xsl:value-of select="@name"/> = getParametersValue(source, "<xsl:value-of select="@name"/>"<xsl:value-of select="$defaultValue"/>);	
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
	
	<xsl:template name="schema">
	static schema(parameters = {}) {
  
    const names = getParametersValue(parameters, "names", {});

    return new Sequence({
      name: names.blockName || "<xsl:value-of select="@name"/>",
      value: [
		<xsl:for-each select="type/sequence//element">
		<xsl:choose>
			<xsl:when test="starts-with(@type, 'asnx:')">
			new <xsl:value-of select="f:asd2asn1js-data-type(substring-after(@type, 'asnx:'))"/>({
				name: "<xsl:value-of select="@name"/>",
			})
			</xsl:when>
			<xsl:when test="parent::optional">
			<xsl:value-of select="@type"/>.schema(
				names.<xsl:value-of select="@name"/> || {
				  names: {
					blockName: "<xsl:value-of select="@name"/>",
				  },
				  optional: true
				}
			)
			</xsl:when>
			<xsl:otherwise>
				<xsl:value-of select="@type"/>.schema(parameters)
			</xsl:otherwise>
		</xsl:choose><xsl:if test="position() != last()">,</xsl:if>
		</xsl:for-each>	
		}
    }
	</xsl:template>
	
	
	<xsl:function name="f:asd2asn1js-data-type">
		<xsl:param name="input"/>
		<xsl:variable name="result">
			<xsl:for-each select="tokenize($input, '-')">
				<xsl:value-of select="concat(substring(., 1, 1), f:lower-case(substring(., 2)))"/>
			</xsl:for-each>
		</xsl:variable>
		<xsl:value-of select="$result"/>
	</xsl:function>
	<xsl:function name="f:lower-case">
		<xsl:param name="input"/>
		<xsl:value-of select="translate($input, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')"/>
	</xsl:function>
	<xsl:function name="f:upper-case">
		<xsl:param name="input"/>
		<xsl:value-of select="translate($input, 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')"/>
	</xsl:function>
</xsl:transform>
