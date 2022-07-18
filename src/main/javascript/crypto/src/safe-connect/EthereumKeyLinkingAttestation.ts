import {SignedLinkedAttestation} from "../asn1/shemas/SignedLinkedAttestation";
import {SignedEthereumKeyLinkingAttestation} from "../asn1/shemas/EthereumKeyLinkingAttestation";
import {AsnParser, AsnSerializer} from "@peculiar/asn1-schema";
import {base64ToUint8array, hexStringToUint8, uint8arrayToBase64} from "../libs/utils";
import {EpochTimeValidity} from "../asn1/shemas/EpochTimeValidity";
import {EthereumKeyLinkingAttestation as KeyLinkSchema} from "../asn1/shemas/EthereumKeyLinkingAttestation";
import {AlgorithmIdentifierASN} from "../asn1/shemas/AuthenticationFramework";


class EthereumKeyLinkingAttestation {

	private readonly linkAttest: SignedEthereumKeyLinkingAttestation;

	protected constructor(linkedAttestation: string, linkedEthereumAddress: string) {

		let addressAttestObj = AsnParser.parse(base64ToUint8array(linkedAttestation), SignedLinkedAttestation);

		this.linkAttest = new SignedEthereumKeyLinkingAttestation();
		this.linkAttest.ethereumKeyLinkingAttestation = new KeyLinkSchema();
		this.linkAttest.ethereumKeyLinkingAttestation.subjectEthereumAddress = hexStringToUint8(linkedEthereumAddress);
		this.linkAttest.ethereumKeyLinkingAttestation.linkedAttestation = addressAttestObj;

		this.linkAttest.ethereumKeyLinkingAttestation.validity = new EpochTimeValidity();
		this.linkAttest.ethereumKeyLinkingAttestation.validity.notBefore = Math.round(Date.now() / 1000);
		this.linkAttest.ethereumKeyLinkingAttestation.validity.notAfter = Math.round((Date.now() / 1000) + 3600);

	}

	async sign(holdingPrivateKey: CryptoKey){

		const linkAttestInfo = AsnSerializer.serialize(this.linkAttest.ethereumKeyLinkingAttestation);

		const linkSig = await window.crypto.subtle.sign(
			{
				name: "RSASSA-PKCS1-v1_5",
				saltLength: 128,
			},
			holdingPrivateKey,
			linkAttestInfo
		);

		this.linkAttest.signingAlgorithm = new AlgorithmIdentifierASN();
		this.linkAttest.signingAlgorithm.algorithm = "1.2.840.113549.1.1.11"; // RSASSA pkcs1 v1.5 with SHA-256
		this.linkAttest.signatureValue = new Uint8Array(linkSig);
	}

	static fromBytes(){

	}

	static fromBase64(){

	}

	getEncoded(){
		return new Uint8Array(AsnSerializer.serialize(this.linkAttest))
	}

	getBase64(){
		return uint8arrayToBase64(this.getEncoded());
	}

	verify(){

	}
}