import {AsnProp, AsnPropTypes} from "@peculiar/asn1-schema";

export class EpochTimeValidity {
	@AsnProp({ type: AsnPropTypes.Integer }) public notBefore: number;
	@AsnProp({ type: AsnPropTypes.Integer }) public notAfter: number;
}