import {AsnProp, AsnPropTypes} from "@peculiar/asn1-schema";
import {PublicKeyInfoValue} from "./AttestationFramework";
import {EpochTimeValidity} from "./EpochTimeValidity";
import {AlgorithmIdentifierASN} from "./AuthenticationFramework";

export class EthereumAddressAttestation {
	@AsnProp({ type: PublicKeyInfoValue }) public subjectPublicKey: PublicKeyInfoValue;
	@AsnProp({ type: AsnPropTypes.OctetString }) public ethereumAddress: Uint8Array;
	@AsnProp({ type: EpochTimeValidity }) public validity: EpochTimeValidity;
	@AsnProp({ type: AsnPropTypes.OctetString, optional: true }) public context?: string;
}

export class SignedEthereumAddressAttestation {
	@AsnProp({ type: EthereumAddressAttestation }) public addressAttestation: EthereumAddressAttestation;
	@AsnProp({ type: AlgorithmIdentifierASN }) public signingAlgorithm: AlgorithmIdentifierASN;
	@AsnProp({ type: AsnPropTypes.BitString }) public signatureValue: Uint8Array;
}