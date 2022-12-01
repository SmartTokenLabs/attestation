import {AsnParser, AsnSerializer} from "@peculiar/asn1-schema";
import {LinkedAttestation, SignedLinkedAttestation} from "../asn1/shemas/SignedLinkedAttestation";
import {KeyPair} from "../libs/KeyPair";
import {base64ToUint8array, hexStringToUint8, uint8arrayToBase64} from "../libs/utils";
import {ethers} from "ethers";
import {AlgorithmIdentifierASN} from "../asn1/shemas/AuthenticationFramework";
import exp = require("constants");

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
		return this.getAttestationData()?.subjectPublicKey;
	}

	getEncoded(){
		return new Uint8Array(AsnSerializer.serialize(this.linkedAttestation))
	}

	getBase64(){
		return uint8arrayToBase64(this.getEncoded());
	}

	sign(attestorKeys: KeyPair){

		const encodedAttest = AsnSerializer.serialize(this.linkedAttestation.attestation[this.TYPE]);

		this.linkedAttestation.signingAlgorithm = new AlgorithmIdentifierASN();
		this.linkedAttestation.signingAlgorithm.algorithm = "1.2.840.10045.4.2"; // Our own internal identifier for ECDSA with keccak256
		this.linkedAttestation.signatureValue = hexStringToUint8(attestorKeys.signRawBytesWithEthereum(Array.from(new Uint8Array(encodedAttest))));
	}

	verify(attestorKeys: KeyPair){

		const encAttestation = AsnSerializer.serialize(this.getAttestationData());

		let payloadHash = hexStringToUint8(ethers.utils.keccak256(new Uint8Array(encAttestation)));

		// TODO: Optionally use address like smart contract validation
		//let address = ethers.utils.recoverAddress(payloadHash, ethers.utils.splitSignature(new Uint8Array(this.linkedAttestation.signatureValue)));

		let pubKey = ethers.utils.recoverPublicKey(payloadHash, ethers.utils.splitSignature(new Uint8Array(this.linkedAttestation.signatureValue)));

		if (pubKey.substring(2) !== attestorKeys.getPublicKeyAsHexStr())
			throw new Error("Attestor public key does not match, expected " + attestorKeys.getPublicKeyAsHexStr() + " got " + pubKey.substring(2));

		let now = Math.round(Date.now() / 1000);
		let data = this.getAttestationData();

		if (!data)
			throw new Error("Linked attestation getAttestationData error");

		if (data.validity.notBefore > now)
			throw new Error("Linked attestation is not yet valid");

		if (data.validity.notAfter < now)
			throw new Error("Linked attestation has expired");
	}
}

export function getValidFromAndExpiry(validity: number, validFrom?: number){

	// block timestamps used in smart contracts to check validity can have large variances
	// to mitigate this issue, validFrom by default is shifted into the past by 10 minutes

	let expiry;

	if (!validFrom) {
		const now = Math.round((Date.now() / 1000));
		validFrom = now - 600; // 10 minutes
		expiry = now + validity;
	} else {
		expiry = validFrom + validity;
	}

	return {validFrom, expiry};
}