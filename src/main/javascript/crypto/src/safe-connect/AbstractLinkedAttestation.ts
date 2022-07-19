import {AsnParser, AsnSerializer} from "@peculiar/asn1-schema";
import {LinkedAttestation, SignedLinkedAttestation} from "../asn1/shemas/SignedLinkedAttestation";
import {KeyPair} from "../libs/KeyPair";
import {base64ToUint8array, hexStringToUint8, uint8arrayToBase64} from "../libs/utils";
import {ethers} from "ethers";

export abstract class AbstractLinkedAttestation {

	abstract TYPE: keyof LinkedAttestation;

	protected linkedAttestation: SignedLinkedAttestation

	fromObject(attestation: SignedLinkedAttestation){
		this.linkedAttestation = attestation;
	}

	fromBytes(asnBytes: Uint8Array){
		this.linkedAttestation = AsnParser.parse(asnBytes, SignedLinkedAttestation);
	}

	fromBase64(base64Attestation: string){
		this.fromBytes(base64ToUint8array(base64Attestation));
	}

	getAttestationData(){
		return this.linkedAttestation.attestation[this.TYPE];
	}

	getSubjectPublicKey(){
		return this.getAttestationData().subjectPublicKey;
	}

	getEncoded(){
		return new Uint8Array(AsnSerializer.serialize(this.linkedAttestation))
	}

	getBase64(){
		return uint8arrayToBase64(this.getEncoded());
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