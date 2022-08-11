import {AsnProp, AsnPropTypes} from "@peculiar/asn1-schema";
import {EpochTimeValidity} from "./EpochTimeValidity";

export class ERC721 {
	@AsnProp({ type: AsnPropTypes.OctetString }) public address: Uint8Array;
	@AsnProp({ type: AsnPropTypes.Integer }) public chainId: number;
	@AsnProp({ type: AsnPropTypes.OctetString, optional: true, repeated: "sequence" }) public tokenIds?: Uint8Array[];
}

export class NFTOwnershipAttestation {
	@AsnProp({ type: AsnPropTypes.Any }) public subjectPublicKey: Uint8Array;
	@AsnProp({ type: ERC721, repeated: "sequence" }) public tokens: ERC721[] = [];
	@AsnProp({ type: EpochTimeValidity }) public validity: EpochTimeValidity;
	@AsnProp({ type: AsnPropTypes.OctetString, optional: true }) public context?: string;
}