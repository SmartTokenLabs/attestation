import {AsnProp, AsnPropTypes, AsnType, AsnTypeTypes} from "@peculiar/asn1-schema";
import {EpochTimeValidity} from "./EpochTimeValidity";
import {AlgorithmIdentifierASN} from "./AuthenticationFramework";
import {SignedNFTOwnershipAttestation} from "./NFTOwnershipAttestation";
import {SignedEthereumAddressAttestation} from "./EthereumAddressAttestation";

@AsnType({ type: AsnTypeTypes.Choice })
export class LinkedAttestation {
	@AsnProp({ type: SignedNFTOwnershipAttestation, context: 0 })
	public nftOwnership?: SignedNFTOwnershipAttestation;
	@AsnProp({ type: SignedEthereumAddressAttestation, context: 1 })
	public ethereumAddress?: SignedEthereumAddressAttestation;
}

export class EthereumKeyLinkingAttestation {
	@AsnProp({ type: AsnPropTypes.OctetString }) public subjectEthereumAddress: Uint8Array;
	@AsnProp({ type: LinkedAttestation }) public linkedAttestation: LinkedAttestation;
	@AsnProp({ type: EpochTimeValidity }) public validity: EpochTimeValidity;
	@AsnProp({ type: AsnPropTypes.OctetString, optional: true }) public context?: string;
}

export class SignedEthereumKeyLinkingAttestation {
	@AsnProp({ type: EthereumKeyLinkingAttestation }) public ethereumKeyLinkingAttestation: EthereumKeyLinkingAttestation;
	@AsnProp({ type: AlgorithmIdentifierASN }) public signingAlgorithm: AlgorithmIdentifierASN;
	@AsnProp({ type: AsnPropTypes.BitString }) public signatureValue: Uint8Array;
}