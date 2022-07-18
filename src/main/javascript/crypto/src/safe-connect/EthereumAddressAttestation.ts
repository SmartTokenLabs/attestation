import {AbstractLinkedAttestation} from "./AbstractLinkedAttestation";
import {LinkedAttestation, SignedLinkedAttestation} from "../asn1/shemas/SignedLinkedAttestation";
import {KeyPair} from "../libs/KeyPair";
import {EthereumAddressAttestation as EthAddressSchema} from "../asn1/shemas/EthereumAddressAttestation";
import {EpochTimeValidity} from "../asn1/shemas/EpochTimeValidity";
import {hexStringToUint8} from "../libs/utils";
import {AsnSerializer} from "@peculiar/asn1-schema";
import {AlgorithmIdentifierASN} from "../asn1/shemas/AuthenticationFramework";

export class EthereumAddressAttestation extends AbstractLinkedAttestation {

	TYPE: keyof LinkedAttestation = "ethereumAddress";

	create(holdingPubKey: Uint8Array, attestedAddress: string, attestorKeys: KeyPair, validity: number){

		this.linkedAttestation = new SignedLinkedAttestation();
		this.linkedAttestation.attestation = new LinkedAttestation()
		this.linkedAttestation.attestation.ethereumAddress = new EthAddressSchema();

		this.linkedAttestation.attestation.ethereumAddress.subjectPublicKey = holdingPubKey;

		const validFrom = Math.round((Date.now() / 1000));
		const expiry = validFrom + validity;

		this.linkedAttestation.attestation.ethereumAddress.validity = new EpochTimeValidity();
		this.linkedAttestation.attestation.ethereumAddress.validity.notBefore = validFrom;
		this.linkedAttestation.attestation.ethereumAddress.validity.notAfter = expiry;

		this.linkedAttestation.attestation.ethereumAddress.ethereumAddress = hexStringToUint8(attestedAddress);

		const encodedAttest = AsnSerializer.serialize(this.linkedAttestation.attestation.ethereumAddress);

		this.linkedAttestation.signingAlgorithm = new AlgorithmIdentifierASN();
		this.linkedAttestation.signingAlgorithm.algorithm = "1.2.840.10045.4.2"; // Our own internal identifier for ECDSA with keccak256
		this.linkedAttestation.signatureValue = hexStringToUint8(attestorKeys.signRawBytesWithEthereum(Array.from(new Uint8Array(encodedAttest))));

	}
}