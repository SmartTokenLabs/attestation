import { AttestationCrypto, Pedestren_G } from "./AttestationCrypto";
import { FullProofOfExponent } from "./FullProofOfExponent";
import { Point } from "./Point";
import { uint8tohex } from "./utils";
import { Verifiable } from "./Verifiable";

export class PublicIdentifierProof implements Verifiable {
    private referenceCommitment: Uint8Array;
    private identifier: string;
    private type: number ;
    private internalPok: FullProofOfExponent;
    private crypto: AttestationCrypto;


    constructor() {
        this.crypto = new AttestationCrypto();
    }

    static fromSecret(commitment: Uint8Array, identifier: string, type: number, secret: bigint) {
        let pok = new AttestationCrypto().computeAttestationProof(secret);
        return PublicIdentifierProof.fromPOK(commitment, identifier, type, pok);
    }

    static fromPOK(commitment: Uint8Array, identifier: string,
    type: number, pok: FullProofOfExponent):PublicIdentifierProof {
        let me = new this();
        me.referenceCommitment = commitment;
        me.identifier = identifier;
        me.type = type;
        me.internalPok = pok;
        me.constructorCheck();
        return me;
    }

    private constructorCheck() {
        if (!this.verify()) {
            throw new Error("Proof, commitment and email not consistent or not valid");
        }
    }
    public getInternalPok(): FullProofOfExponent  {
        return this.internalPok;
    }

    public verify():boolean {
        if (!this.verifyCommitment()) {
            return false;
        }
        if (!new AttestationCrypto().verifyFullProof(this.internalPok)) {
            return false;
        }
        return true;
    }

    private verifyCommitment():boolean {
        let hashedIdentifier:bigint = this.crypto.mapToCurveMultiplier(this.type, this.identifier);
        let hiddenMessagePoint:Point  = Pedestren_G.multiplyDA(hashedIdentifier);
        let expectedCommitment: Uint8Array = this.internalPok.getRiddle().add(hiddenMessagePoint).getEncoded();
        if (uint8tohex(expectedCommitment) != uint8tohex(this.referenceCommitment)) {
            return false;
        }
        return true;
    }
}