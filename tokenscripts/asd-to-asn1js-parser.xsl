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
	<!-- FIXME: Ideally we can get it as a run time parameter once we have clear idea -->
	<xsl:param name="externallyImported" select="('PublicKeyInfo')" />
  
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
<xsl:for-each select="//namedType/@name[. = $externallyImported]">
	import <xsl:value-of select="."/> from "./pki_src/<xsl:value-of select="."/>.js";
</xsl:for-each>		
		<!-- FIXME: handle other imports -->
		<xsl:apply-templates select="namedType[@name = current()//*/@type][not(@name = $externallyImported)]"/>
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
		}
	}	
    static defaultValues(memberName) {
      switch (memberName) {
		<xsl:for-each select="type/sequence/optional">
		case "<xsl:value-of select="element/@name"/>":
			return new <xsl:value-of select="if(element/@type = $externallyImported) then element/@type else element/@name"/>();
		</xsl:for-each>	  
        default:
          throw new Error(`Invalid member name for <xsl:value-of select="@name"/> class: ${memberName}`);
      }
    }
	
	<!-- generate function schema --> 
	<xsl:call-template name="schema"/>
	
	<!-- generate function fromSchema -->
	<xsl:call-template name="fromSchema"/>
	
	<!-- generate function toSchema -->
	<xsl:call-template name="toSchema"/>
	
	<!-- generate function toJSON -->
	<xsl:call-template name="toJSON"/>
	
	<!-- generate function serialize -->
	<xsl:call-template name="serialize"/>
	
		 
}
	</xsl:template>
	
	<xsl:template match="namedType[@name = /asnx:module//*/@type]">
export class <xsl:value-of select="@name"/> {
	constructor(source = {}) {
		if (typeof (source) == "string") {
		  throw new TypeError("Unimplemented: Not accepting string yet.")
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
	
	<!-- generate function fromSchema -->
	<xsl:call-template name="fromSchema"/>
	
	<!-- generate function toSchema -->
	<xsl:call-template name="toSchema">
		
	</xsl:call-template>
	
	<!-- generate function toJSON -->
	<xsl:call-template name="toJSON"/>
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
      name: names.blockName || "<xsl:value-of select="(/*//element[@type = current()/@name]/@name, @name)[1]"/>",
      value: [
		<xsl:for-each select="type/sequence//element">
		<xsl:choose>
		<xsl:when test="starts-with(@type, 'asnx:')">
		new <xsl:value-of select="f:asd2asn1js-data-type(substring-after(@type, 'asnx:'))"/>({
			name: names.<xsl:value-of select="@name"/> || "<xsl:value-of select="@name"/>",
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
			<xsl:value-of select="@type"/>.schema(parameters)</xsl:otherwise>
		</xsl:choose><xsl:if test="position() != last()">,</xsl:if>
		</xsl:for-each>
	  ],
    });
    }
	</xsl:template>
	
	<xsl:template name="fromSchema">
	fromSchema(schema) {
    //region Clear input data first
    clearProps(schema, [
	<xsl:for-each select="type/sequence//element">
	  "<xsl:value-of select="@name"/>",</xsl:for-each>
    ]);
    //endregion

    //region Check the schema is valid
    const asn1 = compareSchema(schema, schema, <xsl:value-of select="@name"/>.schema());

    if (asn1.verified === false)
		throw new Error("Object's schema was not verified against input data for <xsl:value-of select="@name"/>");

    //endregion

    //region Get internal properties from parsed schema
    // noinspection JSUnresolvedVariable
	<xsl:for-each select="type/sequence/*">
	  <xsl:choose>
		<xsl:when test="@type = ('asnx:INTEGER')">
		if ("<xsl:value-of select="@name"/>" in asn1.result) {
		  const <xsl:value-of select="@name"/> = asn1.result["<xsl:value-of select="@name"/>"].valueBlock._valueHex;
		  this.<xsl:value-of select="@name"/> = asn1.result["<xsl:value-of select="@name"/>"].valueBlock._valueHex;
		}
		</xsl:when>
		<xsl:when test="starts-with(@type, 'asnx:') or parent::optional">
			<xsl:if test="@type = ('asnx:OCTET-STRING', 'asnx:BIT-STRING')">
				const <xsl:value-of select="@name"/> = asn1.result.<xsl:value-of select="@name"/>;
				this.<xsl:value-of select="@name"/> = <xsl:value-of select="@name"/>.valueBlock.valueHex;
			</xsl:if>	
		</xsl:when>
		<xsl:when test="self::optional">
			<xsl:for-each select="element">
			if(asn1.result.<xsl:value-of select="@name"/>)
				this.<xsl:value-of select="@name"/> = new <xsl:value-of select="@type"/>({
				  schema: asn1.result.<xsl:value-of select="@name"/>,
				});
			</xsl:for-each>
		</xsl:when>
		<xsl:otherwise>
			this.<xsl:value-of select="@name"/> = new <xsl:value-of select="@type"/>(asn1.result.<xsl:value-of select="@name"/>.valueBeforeDecode);
		</xsl:otherwise>
	  </xsl:choose>
	</xsl:for-each>
    }
	</xsl:template>
	<xsl:template name="toSchema">
	
	<xsl:variable name="notAllPremetive" select="not(type/sequence//element[not(starts-with(@type, 'asnx:'))])"/>
	<xsl:variable name="sequenceName" select="concat(f:lower-case(substring(@name, 1, 1)), substring(@name, 2), 'Sequence')"/>
	<xsl:variable name="elementName" select="//element[@type = current()/@name]/@name"/>
	<xsl:message>1-<xsl:sequence select="."/></xsl:message>
	toSchema() {
    //region Create array for output sequence
    const outputArray = [];
	
	<xsl:choose>
		<xsl:when test="$notAllPremetive">
	const <xsl:value-of select="$sequenceName"/> = new Sequence({
      name: "<xsl:value-of select="$elementName"/>",
      value: [
	  <xsl:for-each select="type/sequence/element">
		new Integer({
          name: "<xsl:value-of select="@name"/>",
          isHexOnly: true,
          valueHex: this.<xsl:value-of select="@name"/>,
        }),</xsl:for-each>
      ],
    });

    // verifying the sequence against schema
    const result = compareSchema(<xsl:value-of select="$sequenceName"/>, <xsl:value-of select="$sequenceName"/>, <xsl:value-of select="@name"/>.schema());
    console.log(result.verified);

    return <xsl:value-of select="$sequenceName"/>;
		</xsl:when>
		<xsl:otherwise>
		
	<xsl:for-each select="type/sequence/*">
	  <xsl:choose>
		<xsl:when test="starts-with(@type, 'asnx:')">
			<xsl:if test="@type = ('asnx:OCTET-STRING', 'asnx:BIT-STRING')">
				outputArray.push(new <xsl:value-of select="f:asd2asn1js-data-type(substring-after(@type, 'asnx:'))"/>({ valueHex: this.<xsl:value-of select="@name"/> }));
			</xsl:if>	
		</xsl:when>
		<xsl:when test="self::optional">
			<xsl:for-each select="element">
			if (this.<xsl:value-of select="@name"/>)
				outputArray.push(new <xsl:value-of select="@type"/>(this.<xsl:value-of select="@name"/>).toSchema());
			</xsl:for-each>
		</xsl:when>
		<xsl:otherwise>
			outputArray.push(this.<xsl:value-of select="@name"/>.toSchema());
		</xsl:otherwise>
	  </xsl:choose>
	</xsl:for-each>
    //region Construct and return new ASN.1 schema for this object
    return (new Sequence({
      name:"<xsl:value-of select="@name"/>",
      value: outputArray,
    }));
    //endregion	
		</xsl:otherwise>
	</xsl:choose>
	
  }
	</xsl:template>
	<xsl:template name="toJSON">
	
	toJSON() {
		const object = {
	
	<xsl:for-each select="type/sequence/element">
	  <xsl:choose>
		<xsl:when test="starts-with(@type, 'asnx:')">
			<xsl:choose>
				<xsl:when test="contains(@type, 'INTEGER')">
					<xsl:value-of select="@name"/>: BigInt("0x" + bufferToHexCodes(this.<xsl:value-of select="@name"/>)),
				</xsl:when>
				<xsl:otherwise>
					<xsl:value-of select="@name"/>: this.<xsl:value-of select="@name"/>,
				</xsl:otherwise>
			</xsl:choose>
		</xsl:when>
		<xsl:when test="self::optional">
			<xsl:for-each select="element">
			if (this.<xsl:value-of select="@name"/>)
				outputArray.push(new <xsl:value-of select="@type"/>(this.<xsl:value-of select="@name"/>).toSchema());
			</xsl:for-each>
		</xsl:when>
		<xsl:otherwise>
			<xsl:value-of select="@name"/>: this.<xsl:value-of select="@name"/>.toJSON(),
		</xsl:otherwise>
	  </xsl:choose>
	</xsl:for-each>
    };
	<xsl:for-each select="type/sequence/optional/element">
	  <xsl:choose>
		<xsl:when test="starts-with(@type, 'asnx:')">
			if(this.<xsl:value-of select="@name"/>)
			<xsl:value-of select="@name"/>: this.<xsl:value-of select="@name"/>,	
		</xsl:when>
		<xsl:when test="parent::optional">
		if(this.<xsl:value-of select="@name"/>)
			object["<xsl:value-of select="@name"/>"] =  this.<xsl:value-of select="@name"/>.toJSON();
		</xsl:when>
		<xsl:otherwise>
			if(this.<xsl:value-of select="@name"/>)
			<xsl:value-of select="@name"/>: this.<xsl:value-of select="@name"/>.toJSON(),
		</xsl:otherwise>
	  </xsl:choose>
	</xsl:for-each>
    return object;
  }
	</xsl:template>
	
	<xsl:template name="serialize">
	<xsl:variable name="variableName" select="concat(f:lower-case(substring(@name, 1, 1)), substring(@name, 2))"/>
	serialize() {
		let sequence = this.toSchema();

		const result = compareSchema(sequence, sequence, <xsl:value-of select="@name"/>.schema());
		console.log(result.verified);

		const <xsl:value-of select="$variableName"/>BER = sequence.toBER(false);
		return new Uint8Array(<xsl:value-of select="$variableName"/>BER)

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
