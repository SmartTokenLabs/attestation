import {CURVE_BN256, Point} from "./Point";
import {Proof} from "../asn1/shemas/ProofOfExponentASN";
import {AsnParser} from "@peculiar/asn1-schema";
import {base64ToUint8array, uint8ToBn, uint8toBuffer, uint8tohex, bnToUint8} from "./utils";
import {Asn1Der} from "./DerUtility";
import {UsageProofOfExponent} from "./UsageProofOfExponent";

export class FullProofOfExponent {
    private riddle: Point;
    private tPoint: Point;
    private challengeResponse: bigint;
    private nonce: Uint8Array;
    public encoding: string;

    private constructor() {}

    static fromData(riddle: Point, tPoint: Point, challengeResponse: bigint, nonce: Uint8Array = new Uint8Array([])) {
        let me = new this();
        me.riddle = riddle;
        me.tPoint = tPoint;
        me.challengeResponse = challengeResponse;
        me.nonce = nonce;
        me.encoding = me.makeEncoding(riddle, tPoint, challengeResponse, nonce);
        return me;
    }

    static fromBytes( uint8data: Uint8Array ) {
        let proof: Proof = AsnParser.parse( uint8toBuffer(uint8data) , Proof);
        return this.fromASNType(proof);
    }

    static fromASNType( proof:Proof ) {

        let riddleEnc: Uint8Array = new Uint8Array(proof.riddle);

        let riddle = Point.decodeFromUint8(riddleEnc, CURVE_BN256 );

        let challengeEnc: Uint8Array = new Uint8Array(proof.challengePoint);
        let challengeResponse = uint8ToBn(challengeEnc);

        let tPointEnc: Uint8Array = new Uint8Array(proof.responseValue);
        let tPoint = Point.decodeFromUint8(tPointEnc, CURVE_BN256 );

        let nonce = new Uint8Array(proof.nonce);

        return this.fromData(riddle, tPoint, challengeResponse, nonce);
    }

    static fromBase64(base64DerEncoded: string) {
        return FullProofOfExponent.fromBytes(base64ToUint8array(base64DerEncoded));
    }

    makeEncoding(riddle: Point, tPoint: Point, challengeResponse: bigint, nonce: Uint8Array = new Uint8Array([])):string{
        let proof = Asn1Der.encode('OCTET_STRING', uint8tohex(riddle.getEncoded()))
            + Asn1Der.encode('OCTET_STRING', challengeResponse.toString(16))
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

    public getChallengeResponse() {
        return this.challengeResponse;
    }

    public getNonce(): Uint8Array {
        return this.nonce;
    }

    public getUsageProofOfExponent(): UsageProofOfExponent {
        return UsageProofOfExponent.fromData(this.tPoint, this.challengeResponse, this.nonce);
    }

    public getDerEncoding(): string {
        return this.encoding;
    }
    
    public getAsnType(): Proof {

        const proof = new Proof();
        proof.nonce = this.getNonce();
        proof.challengePoint = bnToUint8(this.getChallengeResponse());
        proof.riddle = this.getRiddle().getEncoded();
        proof.responseValue = this.getPoint().getEncoded();

        return proof;
    }
}
