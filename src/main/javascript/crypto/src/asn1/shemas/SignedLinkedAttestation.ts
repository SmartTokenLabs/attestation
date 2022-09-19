import {AsnProp, AsnPropTypes, AsnType, AsnTypeTypes} from "@peculiar/asn1-schema";
import {AlgorithmIdentifierASN} from "./AuthenticationFramework";
import {NFTOwnershipAttestation} from "./NFTOwnershipAttestation";
import {EthereumAddressAttestation} from "./EthereumAddressAttestation";

@AsnType({ type: AsnTypeTypes.Choice })
export class LinkedAttestation {
	@AsnProp({ type: NFTOwnershipAttestation, context: 0 })
	public nftOwnership?: NFTOwnershipAttestation;
	@AsnProp({ type: EthereumAddressAttestation, context: 1 })
	public ethereumAddress?: EthereumAddressAttestation;
}

export class SignedLinkedAttestation {
	@AsnProp({ type: LinkedAttestation }) public attestation: LinkedAttestation;
	@AsnProp({ type: AlgorithmIdentifierASN }) public signingAlgorithm: AlgorithmIdentifierASN;
	@AsnProp({ type: AsnPropTypes.BitString }) public signatureValue: Uint8Array;
}