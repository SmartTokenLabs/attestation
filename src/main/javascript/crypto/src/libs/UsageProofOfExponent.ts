import {ProofOfExponentInterface} from "./ProofOfExponentInterface";
import {CURVE_BN256, Point} from "./Point";
import {UsageProof} from "../asn1/shemas/ProofOfExponentASN";
import {AsnParser} from "@peculiar/asn1-schema";
import {base64ToUint8array, bnToUint8, uint8ToBn, uint8toBuffer, uint8tohex} from "./utils";
import {Asn1Der} from "./DerUtility";

export class UsageProofOfExponent implements ProofOfExponentInterface {
    private tPoint: Point;
    private challenge: bigint;
    private encoding: string;
    private encodingBytes: Uint8Array;

    constructor() {
    }

    static fromData(tPoint: Point, challenge: bigint): UsageProofOfExponent {
        let me = new this();
        me.tPoint = tPoint;
        me.challenge = challenge;
        me.encoding = me.makeEncoding(tPoint, challenge);
        return me;
    }

    fromBase64(base64DerEncoded: string) {
        this.encoding = base64DerEncoded;
        this.fromBytes(base64ToUint8array(base64DerEncoded));
    }

    fromBytes(bytes: Uint8Array) {
        this.encodingBytes = bytes;
        // UsageProof

        let usageProof: UsageProof = AsnParser.parse( uint8toBuffer(bytes), UsageProof);

        this.challenge = uint8ToBn( new Uint8Array(usageProof.challengePoint) );
        let tPointEnc = new Uint8Array(usageProof.responseValue);
        this.tPoint = Point.decodeFromHex(uint8tohex(tPointEnc), CURVE_BN256);
    }


    makeEncoding(tPoint: Point, challenge: bigint) {
        let res: string = Asn1Der.encode('OCTET_STRING', uint8tohex(bnToUint8(this.challenge))) +
            Asn1Der.encode('OCTET_STRING', uint8tohex(this.tPoint.getEncoded(false)));
        return Asn1Der.encode('SEQUENCE_30', res);
    }


    public getPoint(): Point {
        return this.tPoint;
    }

    public getChallenge(): bigint {
        return this.challenge;
    }

    public getDerEncoding(): string {
        return this.encoding;
    }

}
