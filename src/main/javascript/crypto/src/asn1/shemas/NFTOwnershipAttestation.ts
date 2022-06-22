import {AsnProp, AsnPropTypes} from "@peculiar/asn1-schema";
import {PublicKeyInfoValue} from "./AttestationFramework";
import {ERC721} from "./NFTAttestation";
import {EpochTimeValidity} from "./EpochTimeValidity";
import {AlgorithmIdentifierASN} from "./AuthenticationFramework";

export class NFTOwnershipAttestation {
	@AsnProp({ type: PublicKeyInfoValue }) public subjectPublicKey: PublicKeyInfoValue;
	@AsnProp({ type: ERC721, repeated: "sequence" }) public tokens: ERC721[] = [];
	@AsnProp({ type: EpochTimeValidity }) public validity: EpochTimeValidity;
	@AsnProp({ type: AsnPropTypes.OctetString, optional: true }) public context?: string;
}

export class SignedNFTOwnershipAttestation {
	@AsnProp({ type: NFTOwnershipAttestation }) public nftOwnershipAttestation: NFTOwnershipAttestation;
	@AsnProp({ type: AlgorithmIdentifierASN }) public signingAlgorithm: AlgorithmIdentifierASN;
	@AsnProp({ type: AsnPropTypes.BitString }) public signatureValue: Uint8Array;
}