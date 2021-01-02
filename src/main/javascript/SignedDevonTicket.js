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

export class DevconTicket {
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
          DevconTicket.defaultValues("devconId")
      );
      this.ticketId = getParametersValue(
          source,
          "ticketId",
          DevconTicket.defaultValues("ticketId")
      );
      this.ticketClass = getParametersValue(
          source,
          "ticketClass",
          DevconTicket.defaultValues("ticketClass")
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
      case "signatureAlgorithm":
        return new AlgorithmIdentifier();

      default:
        throw new Error(
            `Invalid member name for SignedTicket class: ${memberName}`
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
    ]);
    //endregion

    //region Check the schema is valid
    const asn1 = compareSchema(schema, schema, DevconTicket.schema());

    if (asn1.verified === false)
      throw new Error("Object's schema was not verified against input data for DevconTicket");

    //endregion

    //region Get internal properties from parsed schema
    // noinspection JSUnresolvedVariable

    if ("devconId" in asn1.result) {
      const devconId = asn1.result["devconId"].valueBlock._valueHex;
      this.devconId = BigInt("0x" + bufferToHexCodes(devconId));
    }

    if ("ticketId" in asn1.result) {
      const ticketId = asn1.result["ticketId"].valueBlock._valueHex
      this.ticketId = BigInt("0x" + bufferToHexCodes(ticketId));
    }

    if ("ticketClass" in asn1.result) {
      const ticketClass = asn1.result["ticketClass"].valueBlock._valueHex;
      this.ticketClass = BigInt("0x" + bufferToHexCodes(ticketClass));
    }

    //endregion
  }
}

export class SignedDevconTicket {
  //**********************************************************************************
  /**
   * Constructor for Attribute class
   * @param {Object} [source={}] source is an object
   * @param {Object} [source:ArrayBuffer] source is DER encoded
   * @param {Object} [source:String]  source is CER encoded
   */
  constructor(source = {}) {
    if (typeof(source) == "string") {
      throw new TypeError("Not accepting string. (If base64, convert to ArrayBuffer.)")
    }
    if (source instanceof ArrayBuffer) {
      const asn1 = fromBER(source)
      this.fromSchema(asn1.result);
    } else {
      this.ticket = new DevconTicket(source.ticket);

      this.commitment = getParametersValue(
          source,
          "commitment",
          DevconTicket.defaultValues("commitment")
      );

      // TODO: issue #75
      // this.signatureAlgorithm = new AlgorithmIdentifier(source.signatureAlgorithm);

      this.signatureValue = getParametersValue(
          source,
          "signatureValue",
          SignedDevconTicket.defaultValues("signatureValue")
      );
    }
  }
  //**********************************************************************************
  /**
   * Return default values for all class members
   * @param {string} memberName String name for a class member
   */
  static defaultValues(memberName) {
    // TODO: issue #76
    throw new Error("You shouldn't see this error - there is no default to any members of this data object.")
    switch (memberName) {
      case "signatureAlgorithm":
        return new AlgorithmIdentifier();
      case "signatureValue":
        return new BitString();
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
        DevconTicket.schema(parameters),
        new OctetString({
          name: "commitment",
        }),
        /* PublicKeyInfo is specified in schema here but not appearing in the constructed data object.
         * This is because the underlying AlgorithmIdentifier isn't fully implemented and also
         * that this data is not important for the 1st delivery deadline, won't be read by client anyway.
         * TODO: add support for PublicKeyInfo https://github.com/TokenScript/attestation/issues/75
         */
        new Sequence( {
          name: "publicKeyInfo",
          optional: true,
          value: [
            AlgorithmIdentifier.schema(
                names.signatureAlgorithm || {
                  names: {
                    blockName: "signatureAlgorithm",
                  },
                }
            ),
            new BitString({
              name: "publicKey"
            }),
          ]
        }),

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
      "ticket",
      "commitment",
      // TODO: #75
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

    this.ticket = new DevconTicket(asn1.result.ticket.valueBeforeDecode)

    if ("commitment" in asn1.result)
      this.commitment = asn1.result["commitment"].valueBlock.valueHex;

    // TODO: issue #75
    // this.signatureAlgorithm = new AlgorithmIdentifier(asn1.result.signatureAlgorithm);

    const signatureValue = asn1.result.signatureValue;
    this.signatureValue = signatureValue.valueBlock.valueHex;    //endregion
  }
}