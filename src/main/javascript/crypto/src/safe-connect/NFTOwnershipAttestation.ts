import {AbstractLinkedAttestation, getValidFromAndExpiry} from "./AbstractLinkedAttestation";
import {LinkedAttestation, SignedLinkedAttestation} from "../asn1/shemas/SignedLinkedAttestation";
import {ERC721, NFTOwnershipAttestation as NFTOwnershipSchema} from "../asn1/shemas/NFTOwnershipAttestation";
import {KeyPair} from "../libs/KeyPair";
import {EpochTimeValidity} from "../asn1/shemas/EpochTimeValidity";
import {bnToUint8, hexStringToUint8} from "../libs/utils";

export interface IToken {
	address: string,
	chainId: number,
	tokenIds?: bigint[],
}

export class NFTOwnershipAttestation extends AbstractLinkedAttestation {

	TYPE: keyof LinkedAttestation = "nftOwnership";

	// TODO: Implement multi-token interface
	create(holdingPubKey: Uint8Array, tokens: IToken[], attestorKeys: KeyPair, validity: number, context?: Uint8Array, validFrom?: number){

		this.linkedAttestation = new SignedLinkedAttestation();
		this.linkedAttestation.attestation = new LinkedAttestation();
		this.linkedAttestation.attestation.nftOwnership = new NFTOwnershipSchema();

		this.linkedAttestation.attestation.nftOwnership.subjectPublicKey = holdingPubKey;

		const validityInfo = getValidFromAndExpiry(validity, validFrom);

		this.linkedAttestation.attestation.nftOwnership.validity = new EpochTimeValidity();
		this.linkedAttestation.attestation.nftOwnership.validity.notBefore = validityInfo.validFrom;
		this.linkedAttestation.attestation.nftOwnership.validity.notAfter = validityInfo.expiry;

		for (let token of tokens){
			let attToken = new ERC721()
			attToken.address = hexStringToUint8(token.address);
			attToken.chainId = token.chainId;

			if (token.tokenIds) {
				attToken.tokenIds = [];

				for (let bn of token.tokenIds) {
					attToken.tokenIds.push(bnToUint8(bn));
				}
			}

			this.linkedAttestation.attestation.nftOwnership.tokens.push(attToken);
		}

		if (context)
			this.linkedAttestation.attestation.nftOwnership.context = context;

		this.sign(attestorKeys);
	}
}