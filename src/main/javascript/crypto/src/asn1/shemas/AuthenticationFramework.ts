import {AsnProp, AsnPropTypes, AsnType, AsnTypeTypes} from "@peculiar/asn1-schema";

export class AlgorithmIdentifierASN {
    // @AsnProp({ type: AsnPropTypes.ObjectIdentifier }) public algorithm: AsnPropTypes.ObjectIdentifier;// OBJECT IDENTIFIER,
    @AsnProp({ type: AsnPropTypes.ObjectIdentifier }) public algorithm: string;// OBJECT IDENTIFIER,
    @AsnProp({ type: AsnPropTypes.Any, optional: true }) public parameters?: AsnPropTypes.Any;// ANY DEFINED BY algorithm OPTIONAL
}

export class Version {
    @AsnProp({ type: AsnPropTypes.Integer }) public version: number = 0;// Version ::= INTEGER { v1(0), v2(1), v3(2) }
}

@AsnType({ type: AsnTypeTypes.Choice })
class Time {
    @AsnProp({ type: AsnPropTypes.UTCTime})
    public utcTime?: AsnPropTypes.UTCTime;
    @AsnProp({ type: AsnPropTypes.GeneralizedTime })
    public generalizedTime?: Date;
}

export class ValidityValue {
    @AsnProp({ type: Time }) public notBefore: Time;
    @AsnProp({ type: AsnPropTypes.Integer, optional: true }) public notBeforeInt?: number|string;
    @AsnProp({ type: Time }) public notAfter: Time;
    @AsnProp({ type: AsnPropTypes.Integer, optional: true }) public notAfterInt?: number|string;
}

@AsnType({ type: AsnTypeTypes.Choice })
class Validity {
    @AsnProp({ type: ValidityValue, context: 0 })
    public value?: ValidityValue;
    @AsnProp({ type: AsnPropTypes.Integer, context: 1 })
    public null?: null;
}

export class Extension {
    @AsnProp({ type: AsnPropTypes.ObjectIdentifier })
    public extnId: string;
    @AsnProp({ type: AsnPropTypes.Boolean })
    public critical: boolean;
    @AsnProp({ type: AsnPropTypes.OctetString })
    public extnValue: Uint8Array;
}

export class Extensions { //SEQUENCE OF Extension
    @AsnProp({ type: Extension }) public extension: Extension;
}

//
// Extension ::= SEQUENCE {
//     extnId		EXTENSION.&id,
//         critical	BOOLEAN DEFAULT FALSE,
//         extnValue	OCTET STRING
//     -- contains a DER encoding of a value of type &ExtnType
//     -- for the extension object identified by extnId
// }
