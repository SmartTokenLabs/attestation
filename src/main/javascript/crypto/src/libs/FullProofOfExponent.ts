import {CURVE_BN256, Point} from "./Point";
import {Proof} from "../asn1/shemas/ProofOfExponentASN";
import {AsnParser} from "@peculiar/asn1-schema";
import {base64ToUint8array, uint8ToBn, uint8tohex, bnToUint8} from "./utils";
import {Asn1Der} from "./DerUtility";
import {UsageProofOfExponent} from "./UsageProofOfExponent";
import { AttestationCrypto } from "./AttestationCrypto";

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
        let proof: Proof = AsnParser.parse(uint8data, Proof);
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
        let point = bnToUint8(this.getChallengeResponse());
        if (point.length < 32) {
            let prevPoint = point;
            point = new Uint8Array(32);
            point.set(prevPoint, 32 - prevPoint.length);
        }
        proof.challengePoint = point;
        proof.riddle = this.getRiddle().getEncoded();
        proof.responseValue = this.getPoint().getEncoded();

        return proof;
    }

    public validateParameters():boolean {
        try {
            // Validate that points are valid on the given curve, have correct order and are not at infinity

            // if (!this.riddle.validate() || !this.tPoint.validate()){
            if (
                !AttestationCrypto.validatePointToCurve(this.riddle, AttestationCrypto.curve) 
            || !AttestationCrypto.validatePointToCurve(this.tPoint, AttestationCrypto.curve )
            ){
                throw new Error("Point not in the curve");
            }

            // Check the challenge response size
            if (this.challengeResponse <= 0n || this.challengeResponse >= AttestationCrypto.curveOrder) {
                return false;
            }

            // While not strictly needed also check that points are not the generator
            if (this.riddle.equals( AttestationCrypto.G ) || this.riddle.equals( AttestationCrypto.H ) ) {
                return false;
            }

            if (this.tPoint.equals( AttestationCrypto.G ) || this.tPoint.equals( AttestationCrypto.H )) {
                return false;
            }

            return true;

        } catch ( e ) {
          return false;
        }
    }
}
