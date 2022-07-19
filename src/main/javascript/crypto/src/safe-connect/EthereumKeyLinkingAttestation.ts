import {SignedLinkedAttestation} from "../asn1/shemas/SignedLinkedAttestation";
import {SignedEthereumKeyLinkingAttestation} from "../asn1/shemas/EthereumKeyLinkingAttestation";
import {AsnParser, AsnSerializer} from "@peculiar/asn1-schema";
import {base64ToUint8array, hexStringToUint8, uint8arrayToBase64} from "../libs/utils";
import {EpochTimeValidity} from "../asn1/shemas/EpochTimeValidity";
import {EthereumKeyLinkingAttestation as KeyLinkSchema} from "../asn1/shemas/EthereumKeyLinkingAttestation";
import {AlgorithmIdentifierASN} from "../asn1/shemas/AuthenticationFramework";
import {KeyPair} from "../libs/KeyPair";
import {EthereumAddressAttestation} from "./EthereumAddressAttestation";
import {NFTOwnershipAttestation} from "./NFTOwnershipAttestation";

const HOLDING_KEY_ALGORITHM = "RSASSA-PKCS1-v1_5";

export class EthereumKeyLinkingAttestation {

	protected linkAttest: SignedEthereumKeyLinkingAttestation;

	create(linkedAttestation: string, linkedEthereumAddress: string, validity: number, validFrom?: number) {

		let addressAttestObj = AsnParser.parse(base64ToUint8array(linkedAttestation), SignedLinkedAttestation);

		this.linkAttest = new SignedEthereumKeyLinkingAttestation();
		this.linkAttest.ethereumKeyLinkingAttestation = new KeyLinkSchema();
		this.linkAttest.ethereumKeyLinkingAttestation.subjectEthereumAddress = hexStringToUint8(linkedEthereumAddress);
		this.linkAttest.ethereumKeyLinkingAttestation.linkedAttestation = addressAttestObj;

		if (!validFrom)
			validFrom = Math.round((Date.now() / 1000));

		const expiry = validFrom + validity;

		this.linkAttest.ethereumKeyLinkingAttestation.validity = new EpochTimeValidity();
		this.linkAttest.ethereumKeyLinkingAttestation.validity.notBefore = validFrom;
		this.linkAttest.ethereumKeyLinkingAttestation.validity.notAfter = expiry;

	}

	async sign(holdingPrivateKey: CryptoKey){

		const linkAttestInfo = AsnSerializer.serialize(this.linkAttest.ethereumKeyLinkingAttestation);

		const linkSig = await window.crypto.subtle.sign(
			{
				name: HOLDING_KEY_ALGORITHM,
				saltLength: 128,
			},
			holdingPrivateKey,
			linkAttestInfo
		);

		this.linkAttest.signingAlgorithm = new AlgorithmIdentifierASN();
		this.linkAttest.signingAlgorithm.algorithm = "1.2.840.113549.1.1.11"; // RSASSA pkcs1 v1.5 with SHA-256
		this.linkAttest.signatureValue = new Uint8Array(linkSig);
	}

	fromBytes(asnBytes: Uint8Array){
		this.linkAttest = AsnParser.parse(asnBytes, SignedEthereumKeyLinkingAttestation);
	}

	fromBase64(base64Attestation: string){
		this.fromBytes(base64ToUint8array(base64Attestation));
	}

	getEncoded(){
		return new Uint8Array(AsnSerializer.serialize(this.linkAttest))
	}

	getBase64(){
		return uint8arrayToBase64(this.getEncoded());
	}

	getAttestation(){
		return this.linkAttest;
	}

	getLinkedAttestationObject(){

		const signedLinkedAttestation = this.linkAttest.ethereumKeyLinkingAttestation.linkedAttestation;

		let linkedAttestation;

		if (signedLinkedAttestation.attestation.ethereumAddress){
			linkedAttestation = new EthereumAddressAttestation();
			linkedAttestation.fromObject(signedLinkedAttestation);
		} else {
			linkedAttestation = new NFTOwnershipAttestation();
			linkedAttestation.fromObject(signedLinkedAttestation);
		}

		return linkedAttestation;
	}

	async verify(attestorKeys: KeyPair){

		let linkedAttestation = this.getLinkedAttestationObject();

		linkedAttestation.verify(attestorKeys);

		let linkedAttestationPubKey = linkedAttestation.getSubjectPublicKey();

		const encodedLinkAttestation = AsnSerializer.serialize(this.linkAttest.ethereumKeyLinkingAttestation);

		const nftSubjectPubKey = await window.crypto.subtle.importKey(
			"spki",
			new Uint8Array(linkedAttestationPubKey),
			{
				name: HOLDING_KEY_ALGORITHM,
				hash: {name: "SHA-256"}
			},
			true,
			["verify"]
		);

		const valid = await window.crypto.subtle.verify(
			{
				name: HOLDING_KEY_ALGORITHM,
				saltLength: 128,
			},
			nftSubjectPubKey,
			this.linkAttest.signatureValue,
			encodedLinkAttestation
		);

		if (!valid)
			throw new Error("Signature verification failed");

		let now = Math.round(Date.now() / 1000);
		let data = this.linkAttest.ethereumKeyLinkingAttestation;

		if (data.validity.notBefore > now)
			throw new Error("Linked attestation is not yet valid");

		if (data.validity.notAfter < now)
			throw new Error("Linked attestation has expired");
	}
}