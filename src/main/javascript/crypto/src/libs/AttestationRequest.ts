import { Point } from "./Point";
import { Asn1Der } from "./DerUtility";
import {hexStringToArray, uint8ToBn, uint8tohex} from "./utils";
import {KeyPair} from "./KeyPair";
import {AttestationCrypto} from "./AttestationCrypto";
import {ATTESTATION_TYPE} from "./interfaces";
import {FullProofOfExponent} from "./FullProofOfExponent";
import {SignatureUtility} from "./SignatureUtility";
import {AsnParser} from "@peculiar/asn1-schema";
import {Identity} from "../asn1/shemas/AttestationRequest";

let EC = require("elliptic");
let ec = new EC.ec('secp256k1');
const ASN1 = require('@lapo/asn1js');

let sha3 = require("js-sha3");

export interface attestationRequestData {
    request?: string,
    requestSecret?: bigint
}

export class AttestationRequest {
    public signature: string;
    private identity: string;
    private type: number;
    public pok: FullProofOfExponent;
    private keys: KeyPair;
    constructor() {}
    static fromEmail(identity: string){
        let crypto = new AttestationCrypto();
        let keys = KeyPair.createKeys();
        let secret: bigint = crypto.makeSecret();
        let pok:FullProofOfExponent = crypto.computeAttestationProof(secret);
        let request = AttestationRequest.fromData(identity, ATTESTATION_TYPE["mail"], pok, keys);
        let output: attestationRequestData = {
            request: request.getDerEncoding(),
            requestSecret: secret
        }
        return output;
    }
    static fromData(identity: string, type: number, pok: FullProofOfExponent, keys: KeyPair): AttestationRequest {
        let me = new this();
        me.create(identity, type, pok, keys);
        if (!me.verify()) {
            throw new Error("The signature or proof is not valid");
        }
        return me;
    }
    create(identity: string, type: number, pok: FullProofOfExponent, keys: KeyPair){
        this.identity = identity;
        this.type = type;
        this.pok = pok;
        this.keys = keys;

        let ecKey = ec.keyFromPrivate(this.keys.getPrivateAsHexString(), 'hex');
        let encodingHash = sha3.keccak256(hexStringToArray(this.getUnsignedEncoding()))
        let signature = ecKey.sign(encodingHash);
        this.signature = signature.toDER('hex');
        // console.log("signature = " + this.signature);
    }
    getUnsignedEncoding(){
        let res = Asn1Der.encode('VISIBLE_STRING',this.identity) +
            Asn1Der.encode('INTEGER',this.type) +
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

        let res = this.getUnsignedEncoding() +
            pubKeyDer +
            Asn1Der.encode('BIT_STRING', this.signature);
        return Asn1Der.encode('SEQUENCE_30', res);
    }
    static fromBytes(asn1: Uint8Array): AttestationRequest {
        let me = new this();

        let identity: Identity = AsnParser.parse( asn1, Identity);

        me.identity = identity.unsignedIdentity.identifier;
        me.type = identity.unsignedIdentity.type;

        let riddleEnc = new Uint8Array(identity.unsignedIdentity.proof.riddle);
        let challengeEnc = new Uint8Array(identity.unsignedIdentity.proof.challengePoint);
        let tPointEnc = new Uint8Array(identity.unsignedIdentity.proof.responseValue);

        let riddle = Point.decodeFromHex(uint8tohex(riddleEnc) );
        let challenge = uint8ToBn(challengeEnc);
        let tPoint = Point.decodeFromHex(uint8tohex(tPointEnc) );

        me.pok = FullProofOfExponent.fromData(riddle, tPoint, challenge);

        let publicKey = new Uint8Array(identity.publicKey.value.subjectPublicKey);

        me.keys = KeyPair.fromPublicHex(uint8tohex(publicKey));

        let signature = new Uint8Array(identity.signatureValue);
        me.signature = uint8tohex(signature);

        if (!me.verify()) {
            throw new Error("The signature is not valid");
        }

        return me;
    }
    verify():boolean {

        let encodingHash = sha3.keccak256(hexStringToArray(this.getUnsignedEncoding()))
        if (!SignatureUtility.verify(encodingHash, this.signature, this.keys)) {
            return false;
        }
        // console.log('signatureVerify OK');

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
    getIdentity(): string{
        return this.identity;
    }
    getType(): number{
        return this.type;
    }
    getKeys(): KeyPair{
        return this.keys;
    }
}

