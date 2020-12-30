import {
  BitString,
  compareSchema,
  Integer,
  OctetString,
  Sequence,
  fromBER
} from "asn1js";
import { getParametersValue, clearProps, bufferToHexCodes } from "pvutils";
import AlgorithmIdentifier from "./AlgorithmIdentifier.js";

export default class DevconTicket {
  //**********************************************************************************
  /**
   * Constructor for Attribute class
   * @param {Object} [source={}] source is an object
   * @param {Object} [source:ArrayBuffer] source is DER encoded
   * @param {Object} [source:String]  source is CER encoded
   */
  constructor(source = {}) {
    if (typeof (source) == "string") {
      throw new TypeError("Not accepting string. For base64, convert to ArrayBuffer.")
    }
    if (source instanceof ArrayBuffer) {
      const asn1 = fromBER(source)
      this.fromSchema(asn1.result);
    } else {
      this.devconId = getParametersValue(
          source,
          "devconId",
          SignedDevconTicket.defaultValues("devconId")
      );
      this.ticketId = getParametersValue(
          source,
          "ticketId",
          SignedDevconTicket.defaultValues("ticketId")
      );
      this.ticketClass = getParametersValue(
          source,
          "ticketClass",
          SignedDevconTicket.defaultValues("ticketClass")
      );
      this.riddle = getParametersValue(
          source,
          "riddle",
          SignedDevconTicket.defaultValues("riddle")
      );
    }
  }

  static schema(parameters = {}) {
    const names = getParametersValue(parameters, "names", {});

    return new Sequence({
      name: names.blockName || "ticket",
      value: [
        new Integer({
          name: names.devconId || "devconId",
        }),
        new Integer({
          name: names.ticketId || "ticketId",
        }),
        new Integer({
          name: names.ticketClass || "ticketClass",
        }),
        new OctetString({
          name: names.riddle || "riddle",
        })
      ],
    });
  }

  //**********************************************************************************
  /**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
  fromSchema(schema) {
    //region Clear input data first
    clearProps(schema, [
      //   "ticket",
      "devconId",
      "ticketId",
      "ticketClass",
      "riddle",
    ]);
    //endregion

    //region Check the schema is valid
    const asn1 = compareSchema(schema, schema, DevconTicket.schema());

    if (asn1.verified === false)
      throw new Error("Object's schema was not verified against input data for DevconTicket");

    //endregion

    //region Get internal properties from parsed schema
    // noinspection JSUnresolvedVariable

    if ("devconId" in asn1.result)
      this.devconId = asn1.result["devconId"].valueBlock.valueDec;

    if ("ticketId" in asn1.result) {
      const hex = bufferToHexCodes(
          asn1.result["ticketId"].valueBlock._valueHex
      );
      /* Big int does not work directly if we do not use hex conversion */
      const ticketId = BigInt(`0x${hex}`);
      this.ticketId = ticketId;
    }

    if ("ticketClass" in asn1.result)
      this.ticketClass = asn1.result["ticketClass"].valueBlock.valueDec;

    if ("riddle" in asn1.result){
      const hex = bufferToHexCodes(
          asn1.result["riddle"].valueBlock.valueHex
      );

      const riddle = BigInt(`0x${hex}`);
      this.riddle = riddle;
    }
    //endregion
  }
}

class SignedDevconTicket {
  //**********************************************************************************
  /**
   * Constructor for Attribute class
   * @param {Object} [source={}] source is an object
   * @param {Object} [source:ArrayBuffer] source is DER encoded
   * @param {Object} [source:String]  source is CER encoded
   */
  constructor(source = {}) {
    if (typeof(source) == "string") {
      throw new TypeError("Not accepting string. For base64, convert to ArrayBuffer.")
    }
    if (source instanceof ArrayBuffer) {
      const asn1 = fromBER(source)
      this.fromSchema(asn1.result);
    } else {
      this.devconId = getParametersValue(
          source,
          "devconId",
          SignedDevconTicket.defaultValues("devconId")
      );
      this.ticketId = getParametersValue(
          source,
          "ticketId",
          SignedDevconTicket.defaultValues("ticketId")
      );
      this.ticketClass = getParametersValue(
          source,
          "ticketClass",
          SignedDevconTicket.defaultValues("ticketClass")
      );
      this.riddle = getParametersValue(
          source,
          "riddle",
          SignedDevconTicket.defaultValues("riddle")
      );
    }
  }
  //**********************************************************************************
  /**
   * Return default values for all class members
   * @param {string} memberName String name for a class member
   */
  static defaultValues(memberName) {
    switch (memberName) {
      case "devconId":
        return 1;
      case "ticket":
        return 1;
      case "ticketId":
        return 1;
      case "ticketClass":
        return 1;
      case "riddle":
        return 1;	
      case "signatureAlgorithm":
        return new AlgorithmIdentifier();

      default:
        throw new Error(
          `Invalid member name for SignedTicket class: ${memberName}`
        );
    }
  }
  //**********************************************************************************
  /**
   * Return value of pre-defined ASN.1 schema for current class
   *
   * ASN.1 schema:
   * ```asn1
   * CertificateList  ::=  SEQUENCE  {
   *    tbsCertList          TBSCertList,
   *    signatureAlgorithm   AlgorithmIdentifier,
   *    signatureValue       BIT STRING  }
   * ```
   *
   * @param {Object} parameters Input parameters for the schema
   * @returns {Object} asn1js schema object
   */
  static schema(parameters = {}) {
    /**
     * @type {Object}
     * @property {string} [blockName]
     * @property {string} [signatureAlgorithm]
     * @property {string} [signatureValue]
     */
    const names = getParametersValue(parameters, "names", {});

    return new Sequence({
      name: names.blockName || "SignedDevconTicket",
      value: [
        ticket(parameters),
        AlgorithmIdentifier.schema(
          names.signatureAlgorithm || {
            names: {
              blockName: "signatureAlgorithm",
            },
          }
        ),
        new BitString({
          name: names.signatureValue || "signatureValue",
        }),
      ],
    });
  }
  //**********************************************************************************
  /**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
  fromSchema(schema) {
    //region Clear input data first
    clearProps(schema, [
      //   "ticket",
      "ticket.devconId",
      "ticket.ticketId",
      "ticket.ticketClass",
      "ticket.riddle",
      "signatureAlgorithm",
      "signatureValue",
    ]);
    //endregion

    //region Check the schema is valid
    const asn1 = compareSchema(schema, schema, SignedDevconTicket.schema());

    if (asn1.verified === false)
		throw new Error("Object's schema was not verified against input data for SignedDevconTicket");

    //endregion

    //region Get internal properties from parsed schema
    // noinspection JSUnresolvedVariable
    this.ticket = asn1.result.ticket.valueBeforeDecode;

    if ("ticket.devconId" in asn1.result)
		this.devconId = asn1.result["ticket.devconId"].valueBlock.valueDec;

    if ("ticket.ticketId" in asn1.result) {
      const hex = bufferToHexCodes(
        asn1.result["ticket.ticketId"].valueBlock._valueHex
      );
	  /* Big int does not work directly if we do not use hex conversion */
      const ticketId = BigInt(`0x${hex}`);
      this.ticketId = ticketId;
    }

    if ("ticket.ticketClass" in asn1.result)
      this.ticketClass = asn1.result["ticket.ticketClass"].valueBlock.valueDec;

    if ("ticket.riddle" in asn1.result){
		const hex = bufferToHexCodes(
			asn1.result["ticket.riddle"].valueBlock.valueHex
		);
	  
		const riddle = BigInt(`0x${hex}`);
		this.riddle = riddle;
	}
    this.signatureAlgorithm = new AlgorithmIdentifier({
      schema: asn1.result.signatureAlgorithm,
    });
    this.signatureValue = asn1.result.signatureValue;
    //endregion
  }
}