import {AsnProp, AsnPropTypes} from "@peculiar/asn1-schema";
import {EpochTimeValidity} from "./EpochTimeValidity";
import {AlgorithmIdentifierASN} from "./AuthenticationFramework";
import {SignedLinkedAttestation} from "./SignedLinkedAttestation";

export class EthereumKeyLinkingAttestation {
	@AsnProp({ type: AsnPropTypes.OctetString }) public subjectEthereumAddress: Uint8Array;
	@AsnProp({ type: SignedLinkedAttestation }) public linkedAttestation: SignedLinkedAttestation;
	@AsnProp({ type: EpochTimeValidity }) public validity: EpochTimeValidity;
	@AsnProp({ type: AsnPropTypes.OctetString, optional: true }) public context?: Uint8Array;
}

export class SignedEthereumKeyLinkingAttestation {
	@AsnProp({ type: EthereumKeyLinkingAttestation }) public ethereumKeyLinkingAttestation: EthereumKeyLinkingAttestation;
	@AsnProp({ type: AlgorithmIdentifierASN }) public signingAlgorithm: AlgorithmIdentifierASN;
	@AsnProp({ type: AsnPropTypes.BitString }) public signatureValue: Uint8Array;
}