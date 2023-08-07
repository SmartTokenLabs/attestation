import {
    base64ToUint8array,
    ecSignatureToSRVhex,
    hexStringToArray,
    hexStringToUint8,
    logger,
    pemOrBase64Orbase64urlToString,
    SignatureSRV,
    stringToArray,
    uint8arrayToBase64,
    uint8ToBn,
    uint8tohex
} from "./utils";
import {Asn1Der} from "./DerUtility";
import {CURVE_SECP256k1, CURVES, Point} from "./Point";
import {AsnParser} from "@peculiar/asn1-schema";
import {
    PrivateKeyData,
    PrivateKeyInfo, PublicKeyInfoValue,
    SubjectPublicKeyInfo, PrivateKeyDataOpenSSL
} from "../asn1/shemas/AttestationFramework";
import {ethers} from "ethers";
import {Signature} from "../asn1/shemas/Signature";
import {DEBUGLEVEL} from "../config";

let EC = require("elliptic");

export interface KeysArray {[index: string]: KeyPair[]|KeyPair}

export interface KeysConfig {[key: string]: KeyPair|KeyPair[]|string};

export let subtle:any;

if (typeof crypto === "object" && crypto.subtle){
    subtle = crypto.subtle;
} else {
    let webcrypto = require('crypto').webcrypto;
    if (webcrypto) {
        subtle = webcrypto.subtle;
    } else  {
        logger(DEBUGLEVEL.LOW, "Webcrypto not accessible");
        throw new Error("webcrypto.subtle missing");
    }
}

let ec = new EC.ec('secp256k1');

let sha3 = require("js-sha3");

// keys = elliptic.js curves, value = browser subtle curve (also supported by node.js)
// node.js supports 'P-256', 'P-384', 'P-521', 'NODE-ED25519', 'NODE-ED448', 'NODE-X25519', or 'NODE-X448'
const EC_CURVES_SUBTLE:{[index:string]: string|null} = {
    p192: null ,
    p224: null ,
    p256: 'P-256',
    p384: 'P-384',
    p521: 'P-521',
    curve25519: null,
    ed25519: null,
    secp256k1: null,
};

// G x, y values taken from official secp256k1 document
const G = new Point(55066263022277343669578718895168534326250603453777594175500187360389116729240n,
    32670510020758816978083085130507043184471273380659243275938904335757337482424n);

const DEFAULT_ALGORITHM = 'secp256k1';

export class KeyPair {
    private constructor() {}
    private privKey: Uint8Array;
    private pubKey: Uint8Array;
    private algorithm: string;
    private ethereumPrefix: string = "\u0019Ethereum Signed Message:\n";

    private algorithmASNList: {[index:string]: string[]} = {
        secp256k1:  ["3081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f3044042000000000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000000704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101","06052b8104000a"],
        sect283k1:  ["3081f806072a8648ce3d02013081ec020101302506072a8648ce3d0102301a0202011b06092a8648ce3d01020303300902010502010702010c304c042400000000000000000000000000000000000000000000000000000000000000000000000004240000000000000000000000000000000000000000000000000000000000000000000000010449040503213f78ca44883f1a3b8162f188e553cd265f23c1567a16876913b0c2ac245849283601ccda380f1c9e318d90f95d07e5426fe87e45c0e8184698e45962364e34116177dd2259022401ffffffffffffffffffffffffffffffffffe9ae2ed07577265dff7f94451e061e163c61020104"],
        // NIST P-256, secp256r1, prime256v1
        p256: ["3081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff30440420ffffffff00000001000000000000000000000000fffffffffffffffffffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b0441046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551020101"]
    }

    getPrivateAsUint8(): Uint8Array{
        return this.privKey;
    }
    getPrivateAsHexString(): string{
        return uint8tohex(this.privKey);
    }
    getPrivateAsBigInt(): bigint{
        return uint8ToBn(this.privKey);
    }
    static privateFromBigInt(priv: bigint): KeyPair {
        let me = new this();
        me.privKey = new Uint8Array(hexStringToArray(priv.toString(16).padStart(64, '0')));
        return me;
    }

    // hex string 129-130 symbols with leading 04 (it means uncompressed)
    static fromPublicHex(publicHex: string){

        publicHex = publicHex.replace("0x", "");

        if (publicHex.toLowerCase().match(/^[a-f0-9]+$/i) === null) {
            throw new Error('Wrong Hex string input');
        }
        if (publicHex.length < 129 || publicHex.length > 130) {
            throw new Error('Wrong public hex length');
        }
        let me = new this();
        me.pubKey = new Uint8Array(hexStringToArray(publicHex));
        return me;
    }

    static fromPrivateUint8(privateUint: Uint8Array, keyAlg:string = ''){
        if (!privateUint || privateUint.length != 32) {
            throw new Error('Wrong private key. Should be 32 bytes Uint8');
        }
        let me = new this();
        me.privKey = privateUint;
        if (keyAlg && CURVES.hasOwnProperty(keyAlg)){
            me.algorithm = keyAlg;
        } else {
            throw new Error(`Algorithm ${keyAlg} not implemented.`);
        }
        return me;
    }

    static publicFromBase64orPEM(encoded: string): KeyPair {
        return KeyPair.publicFromPEM(pemOrBase64Orbase64urlToString(encoded));
    }

    static publicFromPEM(pem: string): KeyPair {
        const pubUint8 = base64ToUint8array(pem);
        let publicKeyObj: PublicKeyInfoValue = AsnParser.parse(pubUint8, PublicKeyInfoValue);
        return KeyPair.publicFromUint(new Uint8Array(publicKeyObj.publicKey));
    }

    static publicFromUint(key: Uint8Array): KeyPair {
        let me = new this();

        if (key.byteLength != 65) {
            logger(DEBUGLEVEL.LOW, 'Wrong public key length');
            throw new Error('Wrong public key length');
        }
        me.pubKey = new Uint8Array(key);
        return me;
    }

    static publicFromSubjectPublicKeyInfo(spki: SubjectPublicKeyInfo): KeyPair {
        let me = new this();
        if(!spki.value) {
            throw new Error("Key value not defined.");
        }
        me.pubKey = new Uint8Array(spki.value.publicKey);
        return me;
    }

    static publicFromSubjectPublicKeyValue(spki: PublicKeyInfoValue): KeyPair {
        let me = new this();
        me.pubKey = new Uint8Array(spki.publicKey);
        me.algorithm = me.getAlgorithNameFromASN1(uint8tohex(new Uint8Array(spki.algorithm)));
        return me;
    }



    static privateFromKeyInfo(spki: PrivateKeyInfo): KeyPair {
        let me = new this();

        let privateKeyObj: PrivateKeyData = AsnParser.parse( spki.keysData, PrivateKeyData);

        me.algorithm = me.getAlgorithNameFromASN1(uint8tohex(new Uint8Array(spki.algIdent)));

        me.privKey = new Uint8Array(privateKeyObj.privateKey);
        return me;
    }

    static privateFromKeyDataPEM(pem: string): KeyPair {

        const receiverPrivUint8 = base64ToUint8array(pem);
        let privateKeyObj: PrivateKeyData = AsnParser.parse(receiverPrivUint8, PrivateKeyData);

        let me = new this();
        // TODO detect and validate algorithm
        me.algorithm = me.getAlgorithNameFromASN1(uint8tohex(new Uint8Array(privateKeyObj.algDescr)));

        me.privKey = new Uint8Array(privateKeyObj.privateKey);
        return me;

    }

    getAlgorithNameFromASN1(alg: string): string {

        let algEncodings: {[index:string]: string} = {};
        for (const property in this.algorithmASNList) {
            this.algorithmASNList[property].forEach((algAsn1:string)=>{
                algEncodings[algAsn1] = property;
            })
        }

        if (algEncodings.hasOwnProperty(alg)) {
            return algEncodings[alg];
        } else {
            let m = "Unknown algorithm.";
            logger(DEBUGLEVEL.LOW, m);
            throw new Error(m);
        }
    }

    static privateFromPEM(pem: string): KeyPair {
        const receiverPrivUint8 = base64ToUint8array(pem);
        try {
            let privateKeyObj: PrivateKeyInfo = AsnParser.parse(receiverPrivUint8, PrivateKeyInfo);
            return KeyPair.privateFromKeyInfo(privateKeyObj);
        } catch(e){
            // try to decode OpenSSL format
        }
        let privateKeyObj: PrivateKeyDataOpenSSL = AsnParser.parse(receiverPrivUint8, PrivateKeyDataOpenSSL);

        let me = new this();

        if (privateKeyObj.algorithm === "1.3.132.0.10") {
            me.algorithm = "secp256k1"
        } else {
            throw new Error(`Unknown algorithm "${privateKeyObj.algorithm}"`)
        }

        me.privKey = new Uint8Array(privateKeyObj.privateKey);
        return me;

    }

    // Generate a private key
    static async generateKeyAsync(): Promise<KeyPair> {
        // using subtlecrypto to generate a key. note that we are using an AES key
        // as an secp256k1 key here, since browsers don't support the latter;
        // that means all the keys must be created exportable to work with.
        const keyPair = await crypto.subtle.generateKey(
            {
                name: 'AES-GCM',
                length: 256
            },
            true,
            ['encrypt']
        );
        let hex = ['0x'];
        const exported = await crypto.subtle.exportKey("raw", keyPair);

        (new Uint8Array(exported)).forEach(i => {
            var h = i.toString(16);
            if (h.length % 2) { h = '0' + h; }
            hex.push(h);
        });
        // the next line works if AES key is always positive

        return this.privateFromBigInt(BigInt(hex.join('')) % CURVE_SECP256k1.n);
    }

    static createKeys(): KeyPair {
        return this.privateFromBigInt(BigInt('0x'+uint8tohex(crypto.getRandomValues(new Uint8Array(32))) ) % CURVE_SECP256k1.n);
    }

    getPublicKeyAsHexStr(): string {
        if (this.pubKey) {
            return uint8tohex(this.pubKey);
        } else {
            // we can use it to count pubPoint without external lib, but it can not work for some curves, where we need to do BN reduction before compress point
            // if (CURVES.hasOwnProperty(this.algorithm) && EC_CURVES.includes(this.algorithm)) {
            //     let curve = CURVES[this.algorithm];
            //     logger(DEBUGLEVEL.HIGH, 'lets generate public key for ' + this.algorithm);
            //     let PointG = new Point(curve.GX, curve.GY, curve);
            //     let pubPoint = PointG.multiplyDA(mod(this.getPrivateAsBigInt(),curve.n));
            //     logger(DEBUGLEVEL.HIGH, 'point ' + pubPoint.useCurve);
            //     // prefix 04 means it is uncompressed key
            //     return '04' + pubPoint.x.toString(16).padStart(64, '0') + pubPoint.y.toString(16).padStart(64, '0')
            if (CURVES.hasOwnProperty(this.algorithm) && EC_CURVES_SUBTLE.hasOwnProperty(this.algorithm)) {
                let curve = new EC.ec(this.algorithm);
                if (!this.getPrivateAsHexString()) {
                    logger(DEBUGLEVEL.LOW, this);
                    throw new Error("Cant sign. This is only public key.");

                }

                let key = curve.keyFromPrivate(this.getPrivateAsHexString(), 'hex');
                return key.getPublic('hex').toString();
            } else {
                let m = 'Private -> Public key not implemented for that aglorighm - "' + this.algorithm + '"';
                logger(DEBUGLEVEL.LOW, m);
                throw new Error(m);
            }

        }
    }

    getAsnDerPublic():string {
        var pubPoint = this.getPublicKeyAsHexStr();
        // algorithm description hardcoded
        let pubPointTypeDescrDER = '';
        if (!this.algorithm){
            let m = 'algorithm undefined, lets use default.';
            logger(DEBUGLEVEL.VERBOSE, m);
            pubPointTypeDescrDER = this.algorithmASNList[DEFAULT_ALGORITHM][0];
        } else if (!this.algorithmASNList.hasOwnProperty(this.algorithm)){
            let m = 'Fatal Error. Algorithm not implemented yet - '+this.algorithm;
            logger(DEBUGLEVEL.LOW, m);
            throw new Error(m);
        } else {
            pubPointTypeDescrDER = this.algorithmASNList[this.algorithm][0];
        }

        return Asn1Der.encode('SEQUENCE_30',
            pubPointTypeDescrDER +
            Asn1Der.encode('BIT_STRING', pubPoint)
        );
    }

    getAddress(): string {
        var pubPoint = this.getPublicKeyAsHexStr();
        pubPoint = pubPoint.substring(2);
        let hash = sha3.keccak256(hexStringToArray(pubPoint));
        return "0x" + hash.substr(-40).toUpperCase();
    }

    signBytes(bytes: number[]): string{
        if (!this.getPrivateAsHexString()) {
            throw new Error("Cant sign. This is only public key.");
        }

        let ecKey = ec.keyFromPrivate(this.getPrivateAsHexString(), 'hex');
        let encodingHash = sha3.keccak256(bytes)
        let signature = ecKey.sign(encodingHash);
        return signature.toDER('hex');
    }

    signStringWithEthereum(message: string): string{
        if (!this.getPrivateAsHexString()) {
            throw new Error("Cant sign. This is only public key.");
        }

        let ecKey = ec.keyFromPrivate(this.getPrivateAsHexString(), 'hex');
        let finalMsg = this.ethereumPrefix + message.length + message;
        let encodingHash = sha3.keccak256(stringToArray(finalMsg));
        let signature = ecKey.sign(encodingHash);
        return signature.toDER('hex');
    }

    signHexStringWithEthereum(message: string): string{
        return this.signStringWithEthereum('0x' + message);
    }

    signBytesWithEthereum(bytes: number[]): string{
        let message = '0x' + uint8tohex(new Uint8Array(bytes));
        logger(DEBUGLEVEL.HIGH, "message: " + message);
        return this.signStringWithEthereum(message);
    }

    signDeterministicSHA256(bytes: number[]): string{
        let sha256 = Array.from(ethers.utils.arrayify(ethers.utils.sha256(bytes)));
        return this.signBytes(sha256);
    }

    verifyDeterministicSHA256(bytes: number[], signature: string): boolean{
        let sha256 = ethers.utils.sha256(bytes).substr(2);
        let key, sign;

        if (CURVES.hasOwnProperty(this.algorithm) && EC_CURVES_SUBTLE.hasOwnProperty(this.algorithm)) {
            let curve = new EC.ec(this.algorithm);
            key = curve.keyFromPublic(this.getPublicKeyAsHexStr(), 'hex');
        } else {
            let m = 'Elliptic.js curve not implemented for that aglorighm - "' + this.algorithm + '"';
            logger(DEBUGLEVEL.LOW, m);
            throw new Error(m);
        }

        if (signature.length == 128 || signature.length == 130) {
            var m = signature.match(/([a-f\d]{64})/gi);

            if (!m || m.length < 2) {
                throw new Error("Wrong key syntax");
            }
            sign = {
                r: m[0],
                s: m[1]
            };

        } else {
            let signatureAsn1: Signature = AsnParser.parse(hexStringToUint8(signature), Signature);
            sign = {
                r: BigInt(signatureAsn1.r).toString(16).padStart(64,'0'),
                s: BigInt(signatureAsn1.s).toString(16).padStart(64,'0')
            };

        }
        return key.verify(sha256, sign);
    }

    verifyHexStringWithEthereum(message: string, signature: string): boolean{
        let finalMsg = '0x' + message;
        let encodingHash = sha3.keccak256(stringToArray(this.ethereumPrefix + finalMsg.length + finalMsg));
        
        let ecKey = ec.keyFromPublic(this.getPublicKeyAsHexStr(), 'hex');
        var m = signature.match(/([a-f\d]{64})/gi);

        if (!m || m.length < 2) {
            throw new Error("Wrong key syntax");
        }

        let sign = {
            r: m[0],
            s: m[1]
        };

        return ecKey.verify(encodingHash, sign);
    }

    signRawBytesWithEthereum(bytes: number[]): string{
        let encodingHash = ethers.utils.keccak256(bytes).substring(2);
        logger(DEBUGLEVEL.HIGH,`signRawBytesWithEthereum: key: ${this.getAddress()}, hash: ${encodingHash}`);
        if (!this.getPrivateAsHexString()) {
            throw new Error("Cant sign. This is only public key.");
        }
        let ecKey = ec.keyFromPrivate(this.getPrivateAsHexString(), 'hex');
        let signatureInstance: SignatureSRV = ecKey.sign(hexStringToUint8( encodingHash));

        return ecSignatureToSRVhex(signatureInstance, ecKey);
    }

    verifyBytesWithEthereum(bytes: number[], signature: string): boolean{
        if (!bytes || !bytes.length) {
            throw new Error('Missing data to verify');
        }
        if (!signature) {
            throw new Error('Missing signature to verify');
        }

        // let encodingHash = sha3.keccak256(bytes);
        let encodingHash = hexStringToArray(ethers.utils.keccak256(bytes));
        let ecKey = ec.keyFromPublic(this.getPublicKeyAsHexStr(), 'hex');

        logger(DEBUGLEVEL.HIGH, `verifyBytesWithEthereum: key: ${this.getAddress()}, hash: ${uint8tohex(new Uint8Array(encodingHash))}`);

        // TODO add signature conversion
        signature = uint8tohex(KeyPair.anySignatureToRawUint8(signature));

        var m = signature.match(/([a-f\d]{64})/gi);

        if (!m || m.length < 2) {
            throw new Error("Wrong key syntax");
        }

        let sign = {
            r: m[0],
            s: m[1]
        };

        return ecKey.verify(encodingHash, sign);
    }

    getJWTParams(){
        let curve = EC_CURVES_SUBTLE[this.algorithm];
        if (!curve) {
            let m = `Cant create subtleCrypto key for curve '${this.algorithm}'`;
            logger(DEBUGLEVEL.LOW, m);
            throw new Error(m);
        }
        let pub = this.getPublicKeyAsHexStr();

        return {
            crv: curve,
            d: uint8arrayToBase64(this.getPrivateAsUint8()),
            // ext: true,
            key_ops: ["sign"],
            kty: "EC",
            x: uint8arrayToBase64(hexStringToUint8(pub.substr(2,64))),
            y: uint8arrayToBase64(hexStringToUint8(pub.substr(66,64)))
        };
    }

    getSubtlePrivateKey(){
        let curve = EC_CURVES_SUBTLE[this.algorithm];
        return subtle.importKey(
            "jwk",
            this.getJWTParams(),
            {
                name: "ECDSA",
                namedCurve: curve
            },
            true,
            ["sign"]
        );
    }

    getSubtlePublicKey(){
        let curve = EC_CURVES_SUBTLE[this.algorithm];
        
        let getParams = this.getJWTParams();
        let params: { crv: string; d?: string; key_ops: string[]; kty: string; x: string; y: string; } = Object.assign({}, getParams);
        delete params.d;

        params.key_ops = ['verify'];
        return subtle.importKey(
            "jwk",
            params,
            {
                name: "ECDSA",
                namedCurve: curve
            },
            true,
            ["verify"]
        );
    }

    async signStringWithSubtle(msg: string): Promise<ArrayBuffer>{
        return await subtle.sign(
            {
                name: "ECDSA",
                hash: {name: "SHA-256"},
            },
            await this.getSubtlePrivateKey(),
            // ethers.utils.sha256(Uint8Array.from(stringToArray(msg)))
            // subtle sign do the sha256 encoding internally
            Uint8Array.from(stringToArray(msg))
        );
    }

    async verifyStringWithSubtle(signature: Uint8Array, msg: string): Promise<boolean>{
        logger(DEBUGLEVEL.VERBOSE, 'pubkey: ' + this.getPublicKeyAsHexStr() + ' msg:' + msg + ' signature:' + uint8tohex(signature));
        logger(DEBUGLEVEL.VERBOSE, await this.getSubtlePublicKey());

        return await subtle.verify(
            {
                name: "ECDSA",
                hash: {name: "SHA-256"},
            },
            await this.getSubtlePublicKey(),
            signature,
            Uint8Array.from(stringToArray(msg))
        );

    }

    async verifyStringWithSubtleDerSignature(signature: Uint8Array, msg: string): Promise<boolean>{
        let signatureAsn1: Signature = AsnParser.parse(signature, Signature);
        const javaSignatureHexRaw = BigInt(signatureAsn1.r).toString(16).padStart(64,'0') + BigInt(signatureAsn1.s).toString(16).padStart(64,'0');
        return this.verifyStringWithSubtle(hexStringToUint8( javaSignatureHexRaw), msg);
    }

    static anySignatureToRawUint8(derSignature: Uint8Array|string): Uint8Array {

        let signatureUint8;
        if (typeof derSignature == "string") {
            signatureUint8 = hexStringToUint8(derSignature);
        } else {
            signatureUint8 = derSignature;
        }

        if (!signatureUint8 || !signatureUint8.length) {
            throw new Error('Empty signature received')
        }

        let output: Uint8Array;
        switch (signatureUint8.length) {
            case 64:
                logger(DEBUGLEVEL.LOW, `anySignatureToRawUint8 received 64 bytes signature (without v value) = ${uint8tohex(signatureUint8)}`);
            case 65:
                output = signatureUint8;
                break;
                // remove last byte ( v ) value
                // output = signatureUint8.slice(0,64);
                // break;
            case 66:
                // remove 04 at start
                if (signatureUint8[0] != 4) {
                    throw new Error(`Cant recognize signature: ${uint8tohex(signatureUint8)}`);
                }
                output = signatureUint8.slice(1,65);
                break;
            case 70:
            case 71:
            case 72:
                let signatureAsn1: Signature = AsnParser.parse(signatureUint8, Signature);
                output = hexStringToUint8(
                    BigInt(signatureAsn1.r).toString(16).padStart(64,'0') +
                    BigInt(signatureAsn1.s).toString(16).padStart(64,'0'));
                break;
            default:
                let m = 'wrong Signature: ' + uint8tohex(signatureUint8);
                throw new Error(m);
        }
        logger(DEBUGLEVEL.VERBOSE, "ready signature:" + uint8tohex(output));
        return output;
    }

    static parseKeyArrayStrings(keys: {[key: string]: KeyPair[]|KeyPair|string}): KeysArray {

		const keyPairs: {[key: string]: KeyPair|KeyPair[]} = {};

        for (let i in keys){
            if (typeof keys[i] === "string") {
				const keyStringArray = (<string>keys[i]).split("|")

				const keyPairArr: KeyPair[] = [];

				for (const keyStr of keyStringArray){
					keyPairArr.push(KeyPair.publicFromBase64orPEM(keyStr));
				}

				keyPairs[i] = keyPairArr;
			} else {
				if (Array.isArray(keyPairs)){
					keyPairs[i] = keys[i] as KeyPair[];
				} else {
					keyPairs[i] = keys[i] as KeyPair;
				}
			}
        }

        return <KeysArray>keyPairs;
    }

}
