import { AsnSerializer } from "@peculiar/asn1-schema";
import {LinkedAttestation, SignedLinkedAttestation} from "../asn1/shemas/SignedLinkedAttestation";
import {KeyPair} from "../libs/KeyPair";
import {hexStringToUint8} from "../libs/utils";
import {ethers} from "ethers";

export abstract class AbstractLinkedAttestation {

	abstract TYPE: keyof LinkedAttestation;

	private linkedAttestation: SignedLinkedAttestation

	fromObject(attestation: SignedLinkedAttestation){
		this.linkedAttestation = attestation;
	}

	getAttestationData(){
		return this.linkedAttestation.attestation[this.TYPE];
	}

	getSubjectPublicKey(){
		return this.getAttestationData().subjectPublicKey;
	}

	verify(attestorKeys: KeyPair){

		const encAttestation = AsnSerializer.serialize(this.getAttestationData());

		let payloadHash = hexStringToUint8(ethers.utils.keccak256(new Uint8Array(encAttestation)));

		// TODO: Optionally use address like smart contract validation
		//let address = ethers.utils.recoverAddress(payloadHash, ethers.utils.splitSignature(new Uint8Array(this.linkedAttestation.signatureValue)));

		let pubKey = ethers.utils.recoverPublicKey(payloadHash, ethers.utils.splitSignature(new Uint8Array(this.linkedAttestation.signatureValue)));

		if (pubKey.substring(2) !== attestorKeys.getPublicKeyAsHexStr())
			throw new Error("Attestor public key does not match, expected " + attestorKeys.getPublicKeyAsHexStr() + " got " + pubKey.substring(2));

	}
}