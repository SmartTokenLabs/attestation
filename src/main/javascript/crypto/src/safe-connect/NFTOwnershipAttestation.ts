import {AbstractLinkedAttestation} from "./AbstractLinkedAttestation";
import {LinkedAttestation, SignedLinkedAttestation} from "../asn1/shemas/SignedLinkedAttestation";
import {ERC721, NFTOwnershipAttestation as NFTOwnershipSchema} from "../asn1/shemas/NFTOwnershipAttestation";
import {KeyPair} from "../libs/KeyPair";
import {EpochTimeValidity} from "../asn1/shemas/EpochTimeValidity";
import {hexStringToUint8} from "../libs/utils";
import {AlgorithmIdentifierASN} from "../asn1/shemas/AuthenticationFramework";
import {AsnSerializer} from "@peculiar/asn1-schema";

export class NFTOwnershipAttestation extends AbstractLinkedAttestation {

	TYPE: keyof LinkedAttestation = "nftOwnership";

	// TODO: Implement multi-token interface
	create(holdingPubKey: Uint8Array, contractAddress: string, chainId: string, attestorKeys: KeyPair, validity: number){

		this.linkedAttestation = new SignedLinkedAttestation();
		this.linkedAttestation.attestation = new LinkedAttestation();
		this.linkedAttestation.attestation.nftOwnership = new NFTOwnershipSchema();

		this.linkedAttestation.attestation.nftOwnership.subjectPublicKey = holdingPubKey;

		const validFrom = Math.round((Date.now() / 1000));
		const expiry = validFrom + validity;

		this.linkedAttestation.attestation.nftOwnership.validity = new EpochTimeValidity();
		this.linkedAttestation.attestation.nftOwnership.validity.notBefore = validFrom;
		this.linkedAttestation.attestation.nftOwnership.validity.notAfter = expiry;

		let token = new ERC721()
		token.address = hexStringToUint8(contractAddress);
		token.chainId = parseInt(chainId);
		token.tokenId = new Uint8Array([parseInt("1")])

		this.linkedAttestation.attestation.nftOwnership.tokens.push(token);

		const attestedInfo = AsnSerializer.serialize(this.linkedAttestation.attestation.nftOwnership);

		this.linkedAttestation.signingAlgorithm = new AlgorithmIdentifierASN();
		this.linkedAttestation.signingAlgorithm.algorithm = "1.2.840.10045.4.2"; // Our own internal identifier for ECDSA with keccak256
		this.linkedAttestation.signatureValue = hexStringToUint8(attestorKeys.signRawBytesWithEthereum(Array.from(new Uint8Array(attestedInfo))));

	}
}