import {ProofOfExponentInterface} from "./ProofOfExponentInterface";
import {CURVE_BN256, Point} from "./Point";
import {UsageProof} from "../asn1/shemas/ProofOfExponentASN";
import {AsnParser} from "@peculiar/asn1-schema";
import {base64ToUint8array, bnToUint8, uint8ToBn, uint8tohex} from "./utils";
import {Asn1Der} from "./DerUtility";

export class UsageProofOfExponent implements ProofOfExponentInterface {
    private tPoint: Point;
    private challengeResponse: bigint;
    private encoding: string;
    private encodingBytes: Uint8Array;
    private nonce: Uint8Array;

    constructor() {
    }

    static fromData(tPoint: Point, challengeResponse: bigint, nonce: Uint8Array = new Uint8Array([])): UsageProofOfExponent {
        let me = new this();
        me.tPoint = tPoint;
        me.challengeResponse = challengeResponse;
        me.nonce = nonce;
        me.encoding = me.makeEncoding();
        return me;
    }

    fromBase64(base64DerEncoded: string) {
        this.encoding = base64DerEncoded;
        this.fromBytes(base64ToUint8array(base64DerEncoded));
    }

    fromBytes(bytes: Uint8Array) {
        this.encodingBytes = bytes;
        // UsageProof

        let usageProof: UsageProof = AsnParser.parse(bytes, UsageProof);

        this.challengeResponse = uint8ToBn( new Uint8Array(usageProof.challengePoint) );
        let tPointEnc = new Uint8Array(usageProof.responseValue);
        this.nonce = new Uint8Array(usageProof.nonce);
        this.tPoint = Point.decodeFromHex(uint8tohex(tPointEnc), CURVE_BN256);
    }


    makeEncoding() {
        let res: string = Asn1Der.encode('OCTET_STRING', uint8tohex(bnToUint8(this.challengeResponse))) +
            Asn1Der.encode('OCTET_STRING', uint8tohex(this.tPoint.getEncoded(false)))+
            Asn1Der.encode('OCTET_STRING', uint8tohex(this.nonce));
        return Asn1Der.encode('SEQUENCE_30', res);
    }


    public getPoint(): Point {
        return this.tPoint;
    }

    public getChallengeResponse(): bigint {
        return this.challengeResponse;
    }

    public getDerEncoding(): string {
        return this.encoding;
    }

    public getNonce(): Uint8Array {
        return this.nonce;
    }

}
