/**
 * @jest-environment jsdom
 */

import {
    bnToUint8,
    hexStringToUint8,
    stringToArray,
    uint8arrayToBase64,
    uint8tohex,
    testsLogger, base64ToUint8array, hexStringToBase64
} from './libs/utils';
import {readFileSync} from "fs";
import {KeyPair} from "./libs/KeyPair";
import {Authenticator} from "./Authenticator";
import {Asn1Der} from "./libs/DerUtility";
import {DEBUGLEVEL} from "./config";


const querystring = require('querystring');

const PREFIX_PATH = '../../../../build/test-results/';

let useAttestRes: string,
    sessionKey: KeyPair,
    session2Key: KeyPair,
    userKey: KeyPair,
    userPubKey: KeyPair,
    attestorPubKey: KeyPair,
    attestorKey: KeyPair,
    safeconnectKey: KeyPair,

    senderKey: KeyPair,
    senderPubKey: KeyPair,

    sessionSignature: Uint8Array,
    useAttestationJson: string,
    attestationRequestJson: string,
    requestAttestAndUsage: string,
    magicLink: string,

    magicLinkPublicPEM: string,
    magicLinkPrivatePEM: string,

    useRequestAttestationJson: string;
let sessionMessage = "message";
let email = "test@test.ts";
let type = "mail";
let WEB_DOMAIN = "http://wwww.hotelbogota.com";
let ATTESTOR_DOMAIN = "http://wwww.attestation.id";

describe("Utils tests", () => {
    test('uint8tohex test', () => {
        expect(uint8tohex(new Uint8Array([1,2]))).toBe("0102")
    })
});

describe("Read keys and files", () => {

    attestationRequestJson = readFileSync(PREFIX_PATH + 'attestation-request.json', 'utf8');
    attestationRequestJson = attestationRequestJson.split(/\r?\n/).join('');

    const userPrivPEM = readFileSync(PREFIX_PATH + 'user-priv.pem', 'utf8');
    userKey = KeyPair.privateFromPEM(userPrivPEM);

    const userPubPEM = readFileSync(PREFIX_PATH + 'user-pub.pem', 'utf8');
    userPubKey = KeyPair.publicFromBase64orPEM(userPubPEM);

    const senderPubPEM = readFileSync(PREFIX_PATH + 'sender-pub.pem', 'utf8');
    senderPubKey = KeyPair.publicFromBase64orPEM(senderPubPEM);

    const attestorPubPEM = readFileSync(PREFIX_PATH + 'attestor-pub.pem', 'utf8');
    attestorPubKey = KeyPair.publicFromBase64orPEM(attestorPubPEM);

    const attestorPrivPEM = readFileSync(PREFIX_PATH + 'attestor-priv.pem', 'utf8');
    attestorKey = KeyPair.privateFromPEM(attestorPrivPEM);

    const sessionPrivPEM = readFileSync(PREFIX_PATH + 'session-priv.pem', 'utf8');
    sessionKey = KeyPair.privateFromPEM(sessionPrivPEM);

    const senderPrivPEM = readFileSync(PREFIX_PATH + 'sender-priv.pem', 'utf8');
    senderKey = KeyPair.privateFromPEM(senderPrivPEM);

    const session2PrivPEM = readFileSync(PREFIX_PATH + 'session-priv2.pem', 'utf8');
    session2Key = KeyPair.privateFromPEM(session2PrivPEM);

    const safeconnectIssuerPubKeyPem = readFileSync(PREFIX_PATH + 'key-ec.txt', 'utf8');
    safeconnectKey = KeyPair.publicFromBase64orPEM(safeconnectIssuerPubKeyPem);

    useAttestationJson = readFileSync(PREFIX_PATH + 'use-attestation.json', 'utf8');

    magicLink = readFileSync(PREFIX_PATH + 'mah@mah.com.url', 'utf8');

    useRequestAttestationJson = readFileSync(PREFIX_PATH + 'use-and-request-attestation.json', 'utf8');

    magicLink = readFileSync(PREFIX_PATH + 'mah_v2@mah.com.url', 'utf8');
    magicLinkPrivatePEM = readFileSync('../../../../src/test/data/namedEcPrivKey.pem', 'utf8');
    magicLinkPublicPEM = readFileSync('../../../../src/test/data/namedEcPubKey.pem', 'utf8');

    test('Read keys test ok', () => {
        expect(userPubKey.getPublicKeyAsHexStr()).toBe(userKey.getPublicKeyAsHexStr());
    })
});

describe("read public key", () => {
    // Standard PKCS stored key
    const pubKeyPem1 = readFileSync(PREFIX_PATH + 'ticket-issuer-key.pem', 'utf8');
    let addr1 = "0x94085A072E5481D64D6E2165268801B87A362B64";
    // Pure base64 dump
    const keyFile2 = 'MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEOt9mWLpQVOxiOvswFK4GGI0oOZ2GqS2Q6ec0AWIeuVoCuTD+atppPvjMgNLg9qQzJxsDW3zLxnOPFWO/Decnag==';
    let addr2 = "0x17C0B3B51A75F1A001F255A7CAD4FA45529CAC20";
 					

    test('read 2 keys', async () => {
        let key1 = Authenticator.decodePublicKey(pubKeyPem1);
        expect(key1.getAddress().toLocaleLowerCase()).toBe(addr1.toLocaleLowerCase());
        
        let key2 = Authenticator.decodePublicKey(keyFile2);
        expect(key2.getAddress().toLocaleLowerCase()).toBe(addr2.toLocaleLowerCase());
    })
})

describe("read private key", () => {

    let opensslKey = "MHQCAQEEIF4H530+T2FFQjMI0hkaMzR5DfotHzXbhAcq+OxjcM5WoAcGBSuBBAAKoUQDQgAEYOCWsqPOp9lirOB9xIO5zIepnAoIgPfWwRG06XonF8+BdHrPMqe1DzsEwsuIDpVxB9fEpZVbVPkPurFYDk8KAQ=="
    // Standard PKCS stored key
    
    test('read key', async () => {
        let key = KeyPair.privateFromPEM(opensslKey)
        expect(key.getAddress().toLowerCase()).toBe("0xCE88748AEDF95313D96559AB39254F332DFE8F9C".toLowerCase())
    })

    
})

