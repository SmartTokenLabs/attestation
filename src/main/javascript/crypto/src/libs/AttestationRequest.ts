import {CURVE_BN256, Point} from "./Point";
import { Asn1Der } from "./DerUtility";
import {hexStringToArray, uint8ToBn, uint8toBuffer, uint8tohex} from "./utils";
import {KeyPair} from "./KeyPair";
import {AttestationCrypto} from "./AttestationCrypto";
import {ATTESTATION_TYPE} from "./interfaces";
import {FullProofOfExponent} from "./FullProofOfExponent";
import {AsnParser} from "@peculiar/asn1-schema";
import {Identity} from "../asn1/shemas/AttestationRequest";

export interface attestationRequestData {
    request?: string,
    requestSecret?: bigint
}

export class AttestationRequest {
    private type: number;
    public pok: FullProofOfExponent;
    // private keys: KeyPair;
    constructor() {}

    static fromData(type: number, pok: FullProofOfExponent): AttestationRequest {
        let me = new this();
        me.type = type;
        me.pok = pok;
        if (!me.verify()) {
            throw new Error("The proof is not valid");
        }
        return me;
    }

    getDerEncoding(){
        let res = Asn1Der.encode('INTEGER',this.type) +
            this.pok.encoding;
        return Asn1Der.encode('SEQUENCE_30',res);
    }

    static fromBytes(asn1: Uint8Array): AttestationRequest {
        let me = new this();
        console.log('uint8tohex(asn1)');
        console.log(uint8tohex(asn1));

        let identity: Identity = AsnParser.parse( uint8toBuffer(asn1), Identity);

        me.type = identity.type;

        let riddleEnc = new Uint8Array(identity.proof.riddle);
        let challengeEnc = new Uint8Array(identity.proof.challengePoint);
        let tPointEnc = new Uint8Array(identity.proof.responseValue);
        let nonce = new Uint8Array(identity.proof.nonce);

        let riddle = Point.decodeFromHex(uint8tohex(riddleEnc), CURVE_BN256 );
        let challenge = uint8ToBn(challengeEnc);
        let tPoint = Point.decodeFromHex(uint8tohex(tPointEnc), CURVE_BN256 );

        me.pok = FullProofOfExponent.fromData(riddle, tPoint, challenge, nonce);

        if (!me.verify()) {
            throw new Error("Could not verify the proof");
        }
        // console.log('proof OK');
        return me;
    }

    verify():boolean {

        let AttestationCryptoInstance = new AttestationCrypto();

        if (!AttestationCryptoInstance.verifyAttestationRequestProof(this.pok)) {
            return false;
        }

        // console.log('VerifyAttestationRequestProof OK');

        return true;
    }

    getPok(): FullProofOfExponent{
        return this.pok;
    }

    getType(): number{
        return this.type;
    }
}

