import { AttestationCrypto } from "./AttestationCrypto.js";
import { CURVE_BN256, Point } from "./Point.js";
import { Asn1Der } from "./DerUtility.js";
import { uint8tohex } from "./utils.js";
export class ProofOfExponent {
    constructor(base, riddle, tPoint, challenge) {
        this.base = base;
        this.riddle = riddle;
        this.tPoint = tPoint;
        this.challenge = challenge;
        this.encoding = this.makeEncoding();
    }
    static fromArray(baseEnc, riddleEnc, challengeEnc, tPointEnc) {
        // console.log('POK points and challange received= ', baseEnc, riddleEnc, tPointEnc, challengeEnc);
        let base = Point.decodeFromHex(baseEnc, CURVE_BN256);
        let riddle = Point.decodeFromHex(riddleEnc, CURVE_BN256);
        let tPoint = Point.decodeFromHex(tPointEnc, CURVE_BN256);
        let me = new this(base, riddle, tPoint, BigInt('0x' + challengeEnc));
        me.encoding = me.makeEncoding();
        // if (!me.verify()) {
        //     throw new Error("The proof is not valid");
        // }
        return me;
    }
    verify() {
        let crypto = new AttestationCrypto();
        let verify = crypto.verifyProof(this);
        console.log(`verify POK = ${verify}`);
        // TODO refactor into the POK class
        return crypto.verifyProof(this);
    }
    getBase() {
        return this.base;
    }
    getRiddle() {
        return this.riddle;
    }
    getPoint() {
        return this.tPoint;
    }
    getChallenge() {
        return this.challenge;
    }
    makeEncoding() {
        // console.log('POK points and challange encoded= ', uint8tohex(this.base.getEncoded(false)), uint8tohex(this.riddle.getEncoded(false)), uint8tohex(this.tPoint.getEncoded(false)), this.challenge.toString(16));
        let res = Asn1Der.encode('OCTET_STRING', uint8tohex(this.base.getEncoded(false))) +
            Asn1Der.encode('OCTET_STRING', uint8tohex(this.riddle.getEncoded(false))) +
            Asn1Der.encode('OCTET_STRING', this.challenge.toString(16)) +
            Asn1Der.encode('OCTET_STRING', uint8tohex(this.tPoint.getEncoded(false)));
        return Asn1Der.encode('SEQUENCE_30', res);
    }
    getDerEncoding() {
        return this.encoding;
    }
}
