import {AttestationCrypto} from "./AttestationCrypto";
import {SignedAttestation} from "./SignedAttestation";
import {uint8tohex} from "./utils";
import {Asn1Der} from "./DerUtility";
import {AttestableObject} from "./AttestableObject";
import {ProofOfExponentInterface} from "./ProofOfExponentInterface";

declare global {
    interface Window { ethereum: any; }
}

export class AttestedObject {
    private readonly crypto: AttestationCrypto;
    private pok: ProofOfExponentInterface;
    private readonly derEncodedProof: string;
    private encoding: string;
    constructor(
        private attestableObject: AttestableObject,
        private att: SignedAttestation,
        private attestationSecret: bigint ,
        private objectSecret: bigint
    ) {
        this.crypto = new AttestationCrypto();
        this.pok = this.makeProof(attestationSecret, objectSecret, this.crypto);
        this.derEncodedProof = this.pok.getDerEncoding();

        let vec =
            this.attestableObject.getDerEncoding() +
            this.att.getDerEncoding() +
            this.pok.getDerEncoding();
        this.encoding = Asn1Der.encode('SEQUENCE_30', vec);
    }

    private makeProof(attestationSecret: bigint, objectSecret: bigint, crypto: AttestationCrypto): ProofOfExponentInterface {
        // TODO Bob should actually verify the attestable object is valid before trying to cash it to avoid wasting gas
        // Need to decode twice since the standard ASN1 encodes the octet string in an octet string
        // TODO we dont parse that value, because its already parsed to this.riddle
        // let extensions = this.att.getUnsignedAttestation().getExtensions();//.getObjectAt(0));

        // Index in the second DER sequence is 2 since the third object in an extension is the actual value

        // TODO we dont parse that value, because its already parsed to this.riddle
        // let attCom: Uint8Array = new Uint8Array(extensions.extension.extnValue);
        let attCom: Uint8Array = this.att.getUnsignedAttestation().getRiddle();
        let objCom: Uint8Array = this.attestableObject.getCommitment();
        let pok: ProofOfExponentInterface = crypto.computeEqualityProof(uint8tohex(attCom), uint8tohex(objCom), attestationSecret, objectSecret);

        if (!crypto.verifyEqualityProof(uint8tohex(attCom), uint8tohex(objCom), pok)) {
            throw new Error("The redeem proof did not verify");
        }
        return pok;
    }

    getAttestableObject(){
        return this.attestableObject;
    }

    getAtt(){
        return this.att;
    }

    getDerEncodeProof(){
        return this.derEncodedProof;
    }

    // TODO type it
    public getDerEncoding() {
        return this.encoding;
    }
}
