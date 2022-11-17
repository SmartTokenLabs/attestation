import {AbstractLinkedAttestation, getValidFromAndExpiry} from "./AbstractLinkedAttestation";
import {LinkedAttestation, SignedLinkedAttestation} from "../asn1/shemas/SignedLinkedAttestation";
import {KeyPair} from "../libs/KeyPair";
import {EthereumAddressAttestation as EthAddressSchema} from "../asn1/shemas/EthereumAddressAttestation";
import {EpochTimeValidity} from "../asn1/shemas/EpochTimeValidity";
import {hexStringToUint8} from "../libs/utils";

export class EthereumAddressAttestation extends AbstractLinkedAttestation {

	TYPE: keyof LinkedAttestation = "ethereumAddress";

	create(holdingPubKey: Uint8Array, attestedAddress: string, attestorKeys: KeyPair, validity: number, context?: Uint8Array, validFrom?: number){

		this.linkedAttestation = new SignedLinkedAttestation();
		this.linkedAttestation.attestation = new LinkedAttestation()
		this.linkedAttestation.attestation.ethereumAddress = new EthAddressSchema();

		this.linkedAttestation.attestation.ethereumAddress.subjectPublicKey = holdingPubKey;

		const validityInfo = getValidFromAndExpiry(validity, validFrom);

		this.linkedAttestation.attestation.ethereumAddress.validity = new EpochTimeValidity();
		this.linkedAttestation.attestation.ethereumAddress.validity.notBefore = validityInfo.validFrom;
		this.linkedAttestation.attestation.ethereumAddress.validity.notAfter = validityInfo.expiry;

		this.linkedAttestation.attestation.ethereumAddress.ethereumAddress = hexStringToUint8(attestedAddress);

		if (context)
			this.linkedAttestation.attestation.ethereumAddress.context = context;

		this.sign(attestorKeys);
	}
}