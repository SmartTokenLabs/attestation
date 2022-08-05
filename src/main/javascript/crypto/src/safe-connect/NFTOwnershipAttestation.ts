import {AbstractLinkedAttestation} from "./AbstractLinkedAttestation";
import {LinkedAttestation, SignedLinkedAttestation} from "../asn1/shemas/SignedLinkedAttestation";
import {ERC721, NFTOwnershipAttestation as NFTOwnershipSchema} from "../asn1/shemas/NFTOwnershipAttestation";
import {KeyPair} from "../libs/KeyPair";
import {EpochTimeValidity} from "../asn1/shemas/EpochTimeValidity";
import {hexStringToUint8} from "../libs/utils";

export interface IToken {
	address: string,
	tokenId?: bigint,
	chainId?: number,
}

export class NFTOwnershipAttestation extends AbstractLinkedAttestation {

	TYPE: keyof LinkedAttestation = "nftOwnership";

	// TODO: Implement multi-token interface
	create(holdingPubKey: Uint8Array, tokens: IToken[], attestorKeys: KeyPair, validity: number, context?: string, validFrom?: number){

		this.linkedAttestation = new SignedLinkedAttestation();
		this.linkedAttestation.attestation = new LinkedAttestation();
		this.linkedAttestation.attestation.nftOwnership = new NFTOwnershipSchema();

		this.linkedAttestation.attestation.nftOwnership.subjectPublicKey = holdingPubKey;

		if (!validFrom)
			validFrom = Math.round((Date.now() / 1000));

		const expiry = validFrom + validity;

		this.linkedAttestation.attestation.nftOwnership.validity = new EpochTimeValidity();
		this.linkedAttestation.attestation.nftOwnership.validity.notBefore = validFrom;
		this.linkedAttestation.attestation.nftOwnership.validity.notAfter = expiry;

		for (let token of tokens){
			let attToken = new ERC721()
			attToken.address = hexStringToUint8(token.address);
			attToken.chainId = token.chainId;
			attToken.tokenId = new Uint8Array([parseInt("1")])

			this.linkedAttestation.attestation.nftOwnership.tokens.push(attToken);
		}

		if (!context)
			this.linkedAttestation.attestation.nftOwnership.context = context;

		this.sign(attestorKeys);
	}
}