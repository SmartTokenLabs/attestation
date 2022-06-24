import {AsnProp, AsnPropTypes} from "@peculiar/asn1-schema";
import {EpochTimeValidity} from "./EpochTimeValidity";

export class EthereumAddressAttestation {
	@AsnProp({ type: AsnPropTypes.Any }) public subjectPublicKey: Uint8Array;
	@AsnProp({ type: AsnPropTypes.OctetString }) public ethereumAddress: Uint8Array;
	@AsnProp({ type: EpochTimeValidity }) public validity: EpochTimeValidity;
	@AsnProp({ type: AsnPropTypes.OctetString, optional: true }) public context?: string;
}