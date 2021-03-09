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
    private keys: KeyPair;
    constructor() {}
    /*
    static fromEmail(identity: string){
        let crypto = new AttestationCrypto();
        let keys = KeyPair.createKeys();
        let secret: bigint = crypto.makeSecret();
        let pok:FullProofOfExponent = crypto.computeAttestationProof(secret);
        let request = AttestationRequest.fromData(ATTESTATION_TYPE["mail"], pok, keys);
        let output: attestationRequestData = {
            request: request.getDerEncoding(),
            requestSecret: secret
        }
        return output;
    }*/
    static fromData(type: number, pok: FullProofOfExponent, keys: KeyPair): AttestationRequest {
        let me = new this();
        me.create(type, pok, keys);
        if (!me.verify()) {
            throw new Error("The proof is not valid");
        }
        return me;
    }

    static fromTypeAndPok(type: number, pok: FullProofOfExponent): AttestationRequest {
        let me = new this();
        me.type = type;
        me.pok = pok;
        return me;
    }

    create(type: number, pok: FullProofOfExponent, keys: KeyPair){
        this.type = type;
        this.pok = pok;
        this.keys = keys;

        if (!this.verify()) {
            throw new Error("Could not verify the proof");
        }
    }

    getUnsignedEncoding(){
        let res = Asn1Der.encode('INTEGER',this.type) +
            this.pok.encoding;
        return Asn1Der.encode('SEQUENCE_30',res);
    }

    getDerEncoding(){
        // let ecKey = ec.keyFromPrivate(this.keys.getPrivateAsHexString(), 'hex');
        // var pubPoint = ecKey.getPublic().encode('hex');
        var pubPoint = this.keys.getPublicKeyAsHexStr();
        let pubPointTypeDescrDER = "3081EC06072A8648CE3D02013081E0020101302C06072A8648CE3D0101022100FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F3044042000000000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000000704410479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8022100FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141020101";
        let pubKeyDer = Asn1Der.encode('SEQUENCE_30',
            pubPointTypeDescrDER +
            Asn1Der.encode('BIT_STRING', pubPoint)
        );

        let res = this.getUnsignedEncoding() + pubKeyDer;
        return Asn1Der.encode('SEQUENCE_30', res);
    }

    static fromBytes(asn1: Uint8Array, keys: KeyPair): AttestationRequest {
        let me = new this();

        me.keys = keys;

        let identity: Identity = AsnParser.parse( uint8toBuffer(asn1), Identity);

        me.type = identity.identityPayload.type;

        let riddleEnc = new Uint8Array(identity.identityPayload.proof.riddle);
        let challengeEnc = new Uint8Array(identity.identityPayload.proof.challengePoint);
        let tPointEnc = new Uint8Array(identity.identityPayload.proof.responseValue);

        let riddle = Point.decodeFromHex(uint8tohex(riddleEnc), CURVE_BN256 );
        let challenge = uint8ToBn(challengeEnc);
        let tPoint = Point.decodeFromHex(uint8tohex(tPointEnc), CURVE_BN256 );

        me.pok = FullProofOfExponent.fromData(riddle, tPoint, challenge);

        // let publicKey = new Uint8Array(identity.publicKey.value.publicKey);

        me.keys = KeyPair.publicFromSubjectPublicKeyInfo(identity.publicKey);

        if (!me.verify()) {
            throw new Error("Could not verify the proof");
        }

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

    getKeys(): KeyPair{
        return this.keys;
    }

    setKeys(keys: KeyPair){
        this.keys = keys;
    }
}

