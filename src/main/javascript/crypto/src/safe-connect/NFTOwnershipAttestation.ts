import {AbstractLinkedAttestation} from "./AbstractLinkedAttestation";
import {LinkedAttestation} from "../asn1/shemas/SignedLinkedAttestation";

export class NFTOwnershipAttestation extends AbstractLinkedAttestation {

	TYPE: keyof LinkedAttestation = "nftOwnership";

	constructor() {


		super();
	}

	getSubjectPublicKey(): Uint8Array {
		return undefined;
	}
}