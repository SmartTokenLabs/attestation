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
		<xsl:value-of select="@name"/>
		<xsl:call-template name="newLine"/>
		<xsl:call-template name="newLine"/>
		<xsl:text>DEFINITIONS ::=</xsl:text><!--xsl:value-of select="upper-case(@tagDefault)"/><xsl:text> TAGS </xsl:text-->
		<xsl:call-template name="newLine"/>
		<xsl:text>BEGIN</xsl:text>
		<xsl:call-template name="newLine"/>
		<xsl:call-template name="newLine"/>
		<xsl:apply-templates select="node()"/>
		<xsl:text>END</xsl:text>
	</xsl:template>
	<xsl:template match="namedType[type/sequence]">
		<xsl:value-of select="@name"/>
		<xsl:if test="descendant-or-self::element[@name='dataObject']"> { DataObject }</xsl:if> ::= <xsl:value-of select="upper-case(local-name(type/sequence))"/><xsl:text> {</xsl:text><xsl:call-template name="newLine"/>
		<xsl:apply-templates mode="element" select="type/sequence/element[type/sequence]"/>
		<xsl:apply-templates select="type/sequence/node() except type/sequence/element[type/sequence]"/> 
}
		<xsl:call-template name="newLine"/>
		<xsl:call-template name="newLine"/>
		<xsl:apply-templates select="descendant-or-self::element[type/sequence]"/>
	</xsl:template>
	<xsl:template match="namedType[type/choice]">
		<xsl:value-of select="@name"/><xsl:text> ::= CHOICE {</xsl:text><xsl:call-template name="newLine"/>
		<xsl:apply-templates select="type/choice/node()"/> 
}
		<xsl:call-template name="newLine"/>
		<xsl:call-template name="newLine"/>
	</xsl:template>
	<xsl:template match="namedType[type/sequenceOf]">
		<xsl:value-of select="@name"/><xsl:text> ::= SEQUENCE OF </xsl:text>
		<!--xsl:apply-templates select="type/sequenceOf/node()"/-->
		<xsl:value-of select="type/sequenceOf/element/@type"/>
		<xsl:call-template name="newLine"/>
		<xsl:call-template name="newLine"/>
	</xsl:template>
	<xsl:template match="element[type/sequence][descendant-or-self::element[@name='dataObject']]">
		<xsl:value-of select="concat(upper-case(substring(@name,1,1)),substring(@name, 2))"/> { DataObject } ::= <xsl:value-of select="upper-case(local-name(type/sequence))"/><xsl:text> {</xsl:text><xsl:call-template name="newLine"/>
		<xsl:apply-templates select="type/sequence/node()"/> 
}
		<xsl:call-template name="newLine"/>
		<xsl:call-template name="newLine"/>
	</xsl:template>
	
	<xsl:template name="process-element">
		<xsl:variable name="maxLengthForName" select="max(..//element/@name/string-length())"/>
		<xsl:variable name="finalLengthRequired" select="($maxLengthForName - @name/string-length() + 7)"/>
		<xsl:if test="not(@name='item')"><xsl:value-of select="@name"/><xsl:value-of select="substring($vSpaces, 1, $finalLengthRequired)"/></xsl:if><xsl:if test=".[not(@type) and descendant-or-self::element[@name='dataObject']]"> <xsl:value-of select="concat(upper-case(substring(@name,1,1)),substring(@name, 2))"/> { DataObject }</xsl:if><xsl:value-of select="translate(replace(@type, 'asnx:', ''), '-', ' ')"/>
		<xsl:for-each select="type/fromClass">
			<xsl:value-of select="@class"/>.&amp;<xsl:value-of select="@fieldName"/>
		</xsl:for-each>
		<xsl:for-each select="type/constrained">
			<xsl:for-each select="type/fromClass">
				<xsl:value-of select="@class"/>.&amp;<xsl:value-of select="@fieldName"/>
			</xsl:for-each><xsl:for-each select="table">({<xsl:value-of select="@objectSet"/>}<xsl:for-each select="restrictBy">{<xsl:value-of select="concat('@',.)"/>}</xsl:for-each>)</xsl:for-each>
		</xsl:for-each>
		<xsl:for-each select="type/sequenceOf"> SEQUENCE OF <xsl:value-of select="element/@type"/>
		</xsl:for-each><xsl:if test="..[self::optional]"><xsl:value-of select="concat(' ',upper-case(local-name(..)))"/></xsl:if>
	</xsl:template>
	<xsl:template mode="element" match="element">
		<xsl:value-of select="substring($vSpaces, 1, 4)"/>
		<xsl:call-template name="process-element"/><xsl:text>,</xsl:text><xsl:call-template name="newLine"/>
	</xsl:template>
	<xsl:template match="element">
		<xsl:value-of select="substring($vSpaces, 1, 4)"/>
		<xsl:call-template name="process-element"/><xsl:text>,</xsl:text><xsl:call-template name="newLine"/>
	</xsl:template>
	<xsl:template match="element[not(following-sibling::*)]">
		<xsl:value-of select="substring($vSpaces, 1, 4)"/>
		<xsl:call-template name="process-element"/><xsl:if test="..[self::optional[following-sibling::*]]">,<xsl:call-template name="newLine"/></xsl:if>
	</xsl:template>
	<xsl:template match="element[type/choice]" priority="99">
		<xsl:value-of select="substring($vSpaces, 1, 4)"/>
		<xsl:value-of select="@name"/><xsl:value-of select="substring($vSpaces, 1, 7)"/>CHOICE {<xsl:call-template name="newLine"/><xsl:apply-templates select="type/choice/node()"/>
	}<xsl:call-template name="newLine"/>
	</xsl:template>
	<xsl:template match="element[@name='values']">
		<xsl:value-of select="substring($vSpaces, 1, 4)"/>
		<xsl:value-of select="@name"/><xsl:value-of select="substring($vSpaces, 1, 7)"/>
		<xsl:for-each select="type/setOf">
			<xsl:text>SET SIZE (0..MAX) OF </xsl:text>
			<xsl:for-each select="element/type/fromClass">
				<xsl:value-of select="@class"/>.&amp;<xsl:value-of select="@fieldName"/>
			</xsl:for-each>
		</xsl:for-each>
	</xsl:template>
	
	<xsl:template match="optional[element][default]">
		<xsl:value-of select="substring($vSpaces, 1, 4)"/>
		<xsl:for-each select="element">
			<xsl:value-of select="@name"/><xsl:value-of select="substring($vSpaces, 1, 8)"/><xsl:value-of select="translate(replace(@type, 'asnx:', ''), '-', ' ')"/>
		</xsl:for-each><xsl:for-each select="default"><xsl:value-of select="concat(' ', 'DEFAULT',' ', upper-case(@literalValue),',')"/></xsl:for-each>
		<xsl:call-template name="newLine"/>
	</xsl:template>
	<xsl:template match="optional[element[type/tagged]]">
		<xsl:for-each select="element">
			<xsl:apply-templates select="."/>
		</xsl:for-each>
	</xsl:template>
	<xsl:template match="element[type/tagged]" priority="99">
		<xsl:value-of select="substring($vSpaces, 1, (4 * count(ancestor::element)))"/><xsl:value-of select="@name"/><xsl:value-of select="substring($vSpaces, 1, 8)"/>[<xsl:value-of select="type/tagged/@number"/>] <xsl:if test=".[not(@type) and descendant-or-self::element[@name='dataObject']]"> <xsl:value-of select="concat(upper-case(substring(@name,1,1)),substring(@name, 2))"/></xsl:if><xsl:value-of select="string-join((upper-case(type/tagged/@tagging),type/tagged/@type), ' ')"/><xsl:if test="..[not(self::choice or self::sequence)]"><xsl:value-of select="concat(' ', upper-case(local-name(..)))"/></xsl:if><xsl:if test="following-sibling::* or ..[following-sibling::*]">,</xsl:if><xsl:call-template name="newLine"/>
	</xsl:template>
	<xsl:template match="optional[element[type/fromClass]]">
		<xsl:value-of select="substring($vSpaces, 1, 4)"/>
		<xsl:for-each select="element/type">
			<xsl:value-of select="../@name"/><xsl:value-of select="substring($vSpaces, 1, 8)"/><xsl:value-of select="type/tagged/@number"/> <xsl:value-of select="concat(fromClass/@class, '.&amp;', fromClass/@fieldName, ' ',upper-case(local-name(../..)))"/>
		</xsl:for-each>
	</xsl:template>
	<xsl:template match="namedType[not(*)]">
		<xsl:value-of select="@name"/> ::= <xsl:value-of select="translate(replace(@type, 'asnx:', ''), '-', ' ')"/>
		<xsl:call-template name="newLine"/>
		<xsl:call-template name="newLine"/>
	</xsl:template>
	<xsl:template match="namedType[type/setOf]">
		<!--xsl:value-of select="substring($vSpaces, 1, 4)"/-->
		<xsl:value-of select="@name"/> ::= SET <xsl:for-each select="type/setOf/@minSize">SIZE (<xsl:value-of select="."/> .. MAX) </xsl:for-each>OF <xsl:for-each select="type/setOf">
			<xsl:value-of select="@type"/>
			<xsl:value-of select="element/@type"/>
		</xsl:for-each>
		<xsl:call-template name="newLine"/>
		<xsl:call-template name="newLine"/>
	</xsl:template>
	<xsl:template match="namedType[@name='Version' and type/namedNumberList]">
		<xsl:value-of select="@name"/> ::= INTEGER { <xsl:for-each select="type/namedNumberList/namedNumber"><xsl:value-of select="concat(@name,'(',@number,')')"/><xsl:if test="position() != last()">,</xsl:if></xsl:for-each>}
		<xsl:call-template name="newLine"/>
		<xsl:call-template name="newLine"/>
	</xsl:template>
	
	
	<xsl:template match="namedClass[not(*)]">
		<xsl:value-of select="@name"/> ::= <xsl:value-of select="substring-after(@class,'ASN-')"/>
		<xsl:call-template name="newLine"/>
		<xsl:call-template name="newLine"/>
	</xsl:template>
	<xsl:template match="namedClass[class]">
		<xsl:variable name="maxLengthForName" select="max(class/*/@name/string-length())"/>
		<xsl:value-of select="@name"/><xsl:text> ::= CLASS {</xsl:text><xsl:call-template name="newLine"/>
		<xsl:for-each select="class//*[self::typeField or self::valueField]">
			<xsl:variable name="finalLengthRequired" select="($maxLengthForName - @name/string-length() + 16)"/>
			<xsl:value-of select="substring($vSpaces, 1, 4)"/><xsl:value-of select="concat('&amp;',@name)"/>
			<xsl:if test="@type or ..[self::optional]"><xsl:value-of select="substring($vSpaces, 1, $finalLengthRequired)"/></xsl:if>
			<xsl:value-of select="string-join((translate(replace(@type, 'asnx:', ''), '-', ' '), upper-case(local-name(@unique))), ' ')"/><xsl:for-each select="..[self::optional]"><xsl:for-each select="default"><xsl:value-of select="concat('DEFAULT',' ',upper-case(@literalValue),' ')"/></xsl:for-each><xsl:value-of select="upper-case(local-name(.))"/></xsl:for-each>
			<xsl:if test="position()!=last()">,<xsl:call-template name="newLine"/></xsl:if>
		</xsl:for-each> 
}
	WITH SYNTAX { [<xsl:value-of select="concat('&amp;',class//typeField/@name)"/>] <xsl:for-each select="class/optional/valueField">[<xsl:value-of select="concat(upper-case(@name),' &amp;',lower-case(@name))"/>]</xsl:for-each> IDENTIFIED BY <xsl:value-of select="concat('&amp;',class/valueField/@name)"/> }
		<xsl:call-template name="newLine"/>
		<xsl:call-template name="newLine"/>
	</xsl:template>
	
	<xsl:template match="namedObjectSet">
		<xsl:value-of select="@name"/><xsl:text> </xsl:text><xsl:value-of select="@class"/> ::= <xsl:for-each select="objectSet/extension">{ ... }</xsl:for-each>
		<xsl:call-template name="newLine"/>
		<xsl:call-template name="newLine"/>
	</xsl:template>
	
	<xsl:template name="newLine">
		<xsl:value-of select="'&#13;&#10;'" disable-output-escaping="yes"/>
	</xsl:template>
	<!--xsl:function name="f:new-line">
		<xsl:param name="count"/>
	</xsl:function-->
</xsl:transform>
