import {AsnArray, AsnProp, AsnPropTypes, AsnType, AsnTypeTypes} from "@peculiar/asn1-schema";


export class EpochTimeValidity {
    @AsnProp({ type: AsnPropTypes.Integer }) public notBefore: number;
    @AsnProp({ type: AsnPropTypes.Integer }) public notAfter: number;
}

export class SimpleAsnIntSchema {
    @AsnProp({ type: EpochTimeValidity }) public validity: EpochTimeValidity;
}

export class s2 {
    @AsnProp({ type: AsnPropTypes.Integer }) public notBefore: number;
}

