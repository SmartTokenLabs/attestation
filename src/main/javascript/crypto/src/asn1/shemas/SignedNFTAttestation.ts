import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import { NFTAttestationASN } from "./NFTAttestation";


export class SignedNFTAttestationASN {
    @AsnProp({ type: NFTAttestationASN }) public nftAttestation: NFTAttestationASN;
    @AsnProp({ type: AsnPropTypes.Integer, optional: true }) public signingVersion?: number;
    @AsnProp({ type: AsnPropTypes.Any }) public signingAlgorithm: Uint8Array;
    @AsnProp({ type: AsnPropTypes.BitString }) public signatureValue: Uint8Array;
}



