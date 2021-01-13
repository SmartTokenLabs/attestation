import {AsnProp, AsnPropTypes, AsnType, AsnTypeTypes} from "@peculiar/asn1-schema";
import {Null} from "asn1js";

const AsnCRITICAL = false;

export class AlgorithmIdentifierASN {
    @AsnProp({ type: AsnPropTypes.ObjectIdentifier }) public algorithm: AsnPropTypes.ObjectIdentifier;// OBJECT IDENTIFIER,
    //@AsnProp({ type: AsnPropTypes.Any }) public parameters = AsnCRITICAL;// ANY DEFINED BY algorithm OPTIONAL
}

export class Version {
    @AsnProp({ type: AsnPropTypes.Integer }) public version: number = 0;// Version ::= INTEGER { v1(0), v2(1), v3(2) }
}

// export class CertificateSerialNumber {
//     @AsnProp({ type: AsnPropTypes.Integer }) public version: number = 0;
// }

// export class Time {
//     @AsnProp({ type: AsnPropTypes.GeneralizedTime }) public generalizedTime: AsnPropTypes.GeneralizedTime;
// }
@AsnType({ type: AsnTypeTypes.Choice })
class Time {
    @AsnProp({ type: AsnPropTypes.UTCTime})
    public utcTime?: AsnPropTypes.UTCTime;
    @AsnProp({ type: AsnPropTypes.GeneralizedTime })
    public generalizedTime?: AsnPropTypes.GeneralizedTime;
}

export class ValidityValue {
    @AsnProp({ type: Time }) public notBefore = AsnCRITICAL;
    @AsnProp({ type: Time }) public notAfter = AsnCRITICAL;
}

@AsnType({ type: AsnTypeTypes.Choice })
class Validity {
    @AsnProp({ type: ValidityValue, context: 0 })
    public value?: ValidityValue;
    @AsnProp({ type: AsnPropTypes.Integer, context: 1 })
    public null?: Null;
}

//
// Extensions ::= SEQUENCE OF Extension
//
// Extension ::= SEQUENCE {
//     extnId		EXTENSION.&id,
//         critical	BOOLEAN DEFAULT FALSE,
//         extnValue	OCTET STRING
//     -- contains a DER encoding of a value of type &ExtnType
//     -- for the extension object identified by extnId
// }
