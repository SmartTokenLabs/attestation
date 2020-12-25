import {
  BitString,
  compareSchema,
  Integer,
  OctetString,
  Sequence,
} from "asn1js";
import { getParametersValue, clearProps, bufferToHexCodes } from "pvutils";
import AlgorithmIdentifier from "./algorithm_identifier.js";

function ticket(parameters = {}) {
  const names = getParametersValue(parameters, "names", {});

  return new Sequence({
    name: names.blockName || "ticket",
    value: [
      new Integer({
        name: names.ticketId || "ticket.ticketId",
      }),
      new Integer({
        name: names.ticketClass || "ticket.ticketClass",
      }),
      new Integer({
        name: names.conferenceId || "ticket.conferenceId",
      }),
      new OctetString({
        name: names.riddle || "ticket.riddle",
      })
    ],
  });
}

export default class SignedTicket {
  //**********************************************************************************
  /**
   * Constructor for Attribute class
   * @param {Object} [parameters={}]
   * @param {Object} [parameters.schema] asn1js parsed value to initialize the class from
   */
  constructor(parameters = {}) {
    this.ticketId = getParametersValue(
      parameters,
      "ticketId",
      SignedTicket.defaultValues("ticketId")
    );
    this.ticketClass = getParametersValue(
      parameters,
      "ticketClass",
      SignedTicket.defaultValues("ticketClass")
    );
    this.conferenceId = getParametersValue(
      parameters,
      "conferenceId",
      SignedTicket.defaultValues("conferenceId")
    );
	this.riddle = getParametersValue(
      parameters,
      "riddle",
      SignedTicket.defaultValues("riddle")
    );

    //region If input argument array contains "schema" for this object
    if ("schema" in parameters) this.fromSchema(parameters.schema);
    //endregion
  }
  //**********************************************************************************
  /**
   * Return default values for all class members
   * @param {string} memberName String name for a class member
   */
  static defaultValues(memberName) {
    switch (memberName) {
      case "ticket":
        return 1;
      case "ticketId":
        return 1;
      case "ticketClass":
        return 1;
      case "conferenceId":
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
      name: names.blockName || "SignedTicket",
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
      "ticket.ticketId",
      "ticket.ticketClass",
      "ticket.conferenceId",
      "ticket.riddle",
      "signatureAlgorithm",
      "signatureValue",
    ]);
    //endregion

    //region Check the schema is valid
    const asn1 = compareSchema(schema, schema, SignedTicket.schema());

    if (asn1.verified === false)
		throw new Error("Object's schema was not verified against input data for SignedTicket");

    //endregion

    //region Get internal properties from parsed schema
    // noinspection JSUnresolvedVariable
    this.ticket = asn1.result.ticket.valueBeforeDecode;

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

    if ("ticket.conferenceId" in asn1.result)
		this.conferenceId = asn1.result["ticket.conferenceId"].valueBlock.valueDec;

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
