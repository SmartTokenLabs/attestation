import {AsnProp, AsnPropTypes, IAsnConverter} from "@peculiar/asn1-schema";
import * as asn1 from "asn1js"

const EpochIntegerConverter: IAsnConverter = {
	fromASN: (value) => {
		if (value.valueBlock.valueHex.byteLength > 4)
			return value.valueBlock.toString();

		let dv = new DataView(value.valueBlock.valueHex, 0);
		return dv.getUint32(0);
	},
	toASN: (value) => new asn1.Integer({ value: value }),
};

export class EpochTimeValidity {
	@AsnProp({ type: AsnPropTypes.Integer, converter: EpochIntegerConverter }) public notBefore: number;
	@AsnProp({ type: AsnPropTypes.Integer, converter: EpochIntegerConverter }) public notAfter: number;
}