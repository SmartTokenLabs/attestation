import {Point} from "./Point";
import {Proof} from "../asn1/shemas/ProofOfExponentASN";
import {AsnParser} from "@peculiar/asn1-schema";
import {base64ToUint8array, bnToUint8, uint8ToBn, uint8tohex} from "./utils";
import {Asn1Der} from "./DerUtility";
import {UsageProofOfExponent} from "./UsageProofOfExponent";

export class FullProofOfExponent {
    private riddle: Point;
    private tPoint: Point;
    private challenge: bigint;
    private nonce: Uint8Array;
    public encoding: string;

    constructor() {
    }

    static fromData(riddle: Point, tPoint: Point, challenge: bigint, nonce: Uint8Array = new Uint8Array([])) {
        let me = new this();
        me.riddle = riddle;
        me.tPoint = tPoint;
        me.challenge = challenge;
        me.nonce = nonce;
        me.encoding = me.makeEncoding(riddle, tPoint, challenge, nonce);
        return me;
    }

    static fromBase64(base64DerEncoded: string) {
        let me = new this();

        me.encoding = base64DerEncoded;

        let proof: Proof = AsnParser.parse( base64ToUint8array(base64DerEncoded), Proof);

        let riddleEnc: Uint8Array = new Uint8Array(proof.riddle);
        me.riddle = Point.decodeFromHex(uint8tohex(riddleEnc) );

        let challengeEnc: Uint8Array = new Uint8Array(proof.challengePoint);
        me.challenge = uint8ToBn(challengeEnc);

        let tPointEnc: Uint8Array = new Uint8Array(proof.responseValue);
        me.tPoint = Point.decodeFromHex(uint8tohex(tPointEnc) );

        me.nonce = new Uint8Array(proof.nonce);
    }

    makeEncoding(riddle: Point, tPoint: Point, challenge: bigint, nonce: Uint8Array = new Uint8Array([])):string{
        let proof = Asn1Der.encode('OCTET_STRING', uint8tohex(riddle.getEncoded()))
            + Asn1Der.encode('OCTET_STRING', challenge.toString(16))
            + Asn1Der.encode('OCTET_STRING', uint8tohex(tPoint.getEncoded()))
            + Asn1Der.encode('OCTET_STRING', uint8tohex(nonce));

        return Asn1Der.encode('SEQUENCE_30', proof);
    }

    public getRiddle(): Point {
        return this.riddle;
    }

    public getPoint(): Point {
        return this.tPoint;
    }

    public getChallenge() {
        return this.challenge;
    }

    public getNonce(): Uint8Array {
        return this.nonce;
    }

    public getUsageProofOfExponent(): UsageProofOfExponent {
        return UsageProofOfExponent.fromData(this.tPoint, this.challenge, this.nonce);
    }

    public getDerEncoding(): string {
        return this.encoding;
    }
}
