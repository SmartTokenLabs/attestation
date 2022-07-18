import {AbstractLinkedAttestation} from "./AbstractLinkedAttestation";
import {LinkedAttestation} from "../asn1/shemas/SignedLinkedAttestation";

export class EthereumAddressAttestation extends AbstractLinkedAttestation {

	TYPE: keyof LinkedAttestation = "ethereumAddress";

	constructor() {


		super();
	}

	getSubjectPublicKey(): Uint8Array {
		return undefined;
	}
}