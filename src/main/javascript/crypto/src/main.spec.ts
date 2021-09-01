import {
    bnToUint8,
    hexStringToUint8,
    stringToArray,
    uint8arrayToBase64,
    uint8tohex,
    testsLogger
} from './libs/utils';
import {readFileSync} from "fs";
import {KeyPair} from "./libs/KeyPair";
import {Authenticator} from "./Authenticator";
import {Asn1Der} from "./libs/DerUtility";
import {DEBUGLEVEL} from "./config";

let EC = require("elliptic");

const PREFIX_PATH = '../../../../build/test-results/';

let useAttestRes: string,
    sessionKey: KeyPair,
    session2Key: KeyPair,
    userKey: KeyPair,
    attestorPubKey: KeyPair,
    attestorKey: KeyPair,
    sessionSignature: Uint8Array,
    useAttestationJson: string,
    attestationRequestJson: string,
    requestAttestAndUsage: string,
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
    let userPubKey = KeyPair.publicFromPEM(userPubPEM);

    const attestorPubPEM = readFileSync(PREFIX_PATH + 'attestor-pub.pem', 'utf8');
    attestorPubKey = KeyPair.publicFromPEM(attestorPubPEM);

    const attestorPrivPEM = readFileSync(PREFIX_PATH + 'attestor-priv.pem', 'utf8');
    attestorKey = KeyPair.privateFromPEM(attestorPrivPEM);

    const sessionPrivPEM = readFileSync(PREFIX_PATH + 'session-priv.pem', 'utf8');
    sessionKey = KeyPair.privateFromPEM(sessionPrivPEM);

    const session2PrivPEM = readFileSync(PREFIX_PATH + 'session-priv2.pem', 'utf8');
    session2Key = KeyPair.privateFromPEM(session2PrivPEM);

    useAttestationJson = readFileSync(PREFIX_PATH + 'use-attestation.json', 'utf8');

    useRequestAttestationJson = readFileSync(PREFIX_PATH + 'use-and-request-attestation.json', 'utf8');

    test('Read keys test ok', () => {
        expect(userPubKey.getPublicKeyAsHexStr()).toBe(userKey.getPublicKeyAsHexStr());
    })
});

describe("Subtle import test", () => {
    let res: boolean;
    let messageToSign = 'message';
    const signatureBin = readFileSync(PREFIX_PATH + 'signature.bin');

    test('Session key sign+verify message', async () => {
        try {
            let subtleSignature = new Uint8Array( await sessionKey.signStringWithSubtle(messageToSign) );
             res = await sessionKey.verifyStringWithSubtle(subtleSignature, messageToSign);
            testsLogger(DEBUGLEVEL.HIGH, 'direct sign-verify state: ' + res + ', signature = ' + uint8tohex(subtleSignature) );
        } catch (e){
            testsLogger(DEBUGLEVEL.LOW, 'Import key Error. ',e);
        }

        expect(res).toBe(true);

    })

    test('Session key + verify saved signature(ec)', async () => {

        try {
            res = sessionKey.verifyDeterministicSHA256(stringToArray(messageToSign), uint8tohex(new Uint8Array(signatureBin)));
        } catch (e) {
            let m = 'verifyDeterministicSHA256 Error. '+e;
            testsLogger(DEBUGLEVEL.LOW, m);
        }

        expect(res).toBe(true);
    })

    test('Session key + verify saved signature(subtle)', async () => {

        try {
            res = await sessionKey.verifyStringWithSubtleDerSignature(Uint8Array.from(signatureBin), messageToSign);
        } catch (e) {
            let m = 'verifyStringWithSubtleDerSignature Error. '+e;
            testsLogger(DEBUGLEVEL.LOW, m);
            // throw new Error(m);
        }

        expect(res).toBe(true);
    })
});

describe("Attestation request/construct", () => {


    test("Construct Attestation(from ready attest request)", () => {

        let ATTESTOR_DOMAIN = "http://wwww.attestation.id"

        let attestationResult = Authenticator.constructAttest(attestorKey,'AlphaWallet', 60*60*1000, attestationRequestJson, ATTESTOR_DOMAIN);

        testsLogger(DEBUGLEVEL.HIGH, "attestationResult = " + attestationResult);
        // OK if no Errors
        expect(1).toBe(1);

    });

    test('Authenticator.requestAttest', async () => {

        let secret = BigInt(12345);
        let receiverId = "test@test.com";
        let ATTESTOR_DOMAIN = "http://wwww.attestation.id";
        let attestJson = await Authenticator.requestAttest(receiverId, "mail", ATTESTOR_DOMAIN, secret, userKey);
        attestationRequestJson = attestJson;
        testsLogger(DEBUGLEVEL.HIGH, `attestJson = ${attestJson}`);
        // OK if no Errors
        expect(1).toBe(1);
    })

    test("Construct Attestation(from generated attest request)", () => {

        let ATTESTOR_DOMAIN = "http://wwww.attestation.id"

        let attestRes = Authenticator.constructAttest(attestorKey,'AlphaWallet', 24*60*60*1000, attestationRequestJson, ATTESTOR_DOMAIN);

        testsLogger(DEBUGLEVEL.MEDIUM, "attestRes = " + attestRes);
        testsLogger(DEBUGLEVEL.MEDIUM, "base64 = " + uint8arrayToBase64(hexStringToUint8(attestRes)));
        testsLogger(DEBUGLEVEL.MEDIUM, "base64 = " + uint8arrayToBase64(hexStringToUint8(Asn1Der.encode('SEQUENCE_30', Asn1Der.encode('OCTET_STRING', uint8tohex(bnToUint8(12345n)))))));
        // OK if no Errors
        expect(1).toBe(1);

    });

});



describe("executeEipFlow", () => {

    test('executeEipFlow - signMessage', async () => {

        try {
            sessionSignature = new Uint8Array(await sessionKey.signStringWithSubtle(sessionMessage));
        } catch (e) {
            testsLogger(DEBUGLEVEL.LOW, e);
            // throw new Error('signStringWithSubtle failed');
        }
        expect(1).toBe(1);
        testsLogger(DEBUGLEVEL.MEDIUM, `sessionKey = ` + sessionKey.getAddress());
        testsLogger(DEBUGLEVEL.MEDIUM, `session signature = ` + uint8tohex(sessionSignature));

    })

    test('executeEipFlow - verify-usage(external json and subtle signature)', async () => {
        let res;
        try {
            res = await Authenticator.verifyUsage(
                // useAttestRes,
                useAttestationJson,
                attestorPubKey,
                sessionMessage,
                WEB_DOMAIN,
                sessionSignature);
            testsLogger(DEBUGLEVEL.HIGH, `verifyUsage result = ${res}`);
        } catch (e) {
            testsLogger(DEBUGLEVEL.LOW, e);
            throw new Error('verifyUsage failed');
        }
        expect(res).toBe("SUCCESSFULLY validated usage request!");

    })

    test('executeEipFlow - useAttest', async () => {

        const attestationPEM = readFileSync(PREFIX_PATH + 'attestation.crt', 'utf8');
        const attestationSecretPEM = readFileSync(PREFIX_PATH + 'attestation-secret.pem', 'utf8');

        try {
            useAttestRes = await Authenticator.useAttest(
                attestationPEM,
                attestationSecretPEM,
                attestorPubKey,
                email,
                type,
                WEB_DOMAIN,
                sessionKey,
                userKey);
            useAttestationJson = useAttestRes;
            testsLogger(DEBUGLEVEL.HIGH, `useAttestRes = ${useAttestRes}`);
        } catch (e) {
            testsLogger(DEBUGLEVEL.LOW, e);
            throw new Error('useAttestRes failed');
        }

        // if no Errors then its OK
        expect(1).toBe(1);
    })

    test('executeEipFlow - verify-usage(generated JSON and external signature)', async () => {
        let res;
        const sessionSignatureBin = readFileSync(PREFIX_PATH + 'signature.bin');
        sessionSignature = new Uint8Array(sessionSignatureBin);
        try {
            res = await Authenticator.verifyUsage(
                // useAttestRes,
                useAttestationJson,
                attestorPubKey,
                sessionMessage,
                WEB_DOMAIN,
                sessionSignature);
            testsLogger(DEBUGLEVEL.HIGH, `verifyUsage result = ${res}`);
        } catch (e) {
            testsLogger(DEBUGLEVEL.LOW, e);
            throw new Error('verifyUsage failed');
        }
        expect(res).toBe("SUCCESSFULLY validated usage request!");

    })





});

describe("executeCombinedEipFlow", () => {

    const attestationSecretPEM = readFileSync(PREFIX_PATH + 'attestation-secret.pem', 'utf8');

    const sessionSignatureBin2 = readFileSync(PREFIX_PATH + 'signature2.bin');
    const sessionSignature2 = new Uint8Array(sessionSignatureBin2);

    test('constructAttest (java-generated request-attest-and-usage)', async () => {

        let attestationRequestJson = readFileSync(PREFIX_PATH + 'use-and-request-attestation.json', 'utf8');
        attestationRequestJson = attestationRequestJson.split(/\r?\n/).join('');
        let ATTESTOR_DOMAIN = "http://wwww.attestation.id"

        let attestRes = Authenticator.constructAttest(attestorKey,'AlphaWallet', 60*60*1000, attestationRequestJson, ATTESTOR_DOMAIN);

        testsLogger(DEBUGLEVEL.VERBOSE, attestRes);
        // if no Errors then its OK
        expect(1).toBe(1);
    })

    test('verify-usage(java-generated request-attest-and-usage)', async () => {
        let res;
        try {
            res = await Authenticator.verifyUsage(
                // useAttestRes,
                useRequestAttestationJson,
                attestorPubKey,
                sessionMessage,
                ATTESTOR_DOMAIN,
                sessionSignature2);
            testsLogger(DEBUGLEVEL.MEDIUM, `verifyUsage result = ${res}`);
        } catch (e) {
            testsLogger(DEBUGLEVEL.LOW, e);
            throw new Error('verifyUsage failed');
        }
        expect(res).toBe("SUCCESSFULLY validated usage request!");

    })

    test('request-attest-and-usage', async () => {

        try {
            requestAttestAndUsage = await Authenticator.requestAttestAndUsage(
                userKey,
                "test@test.ts",
                "mail",
                ATTESTOR_DOMAIN,
                attestationSecretPEM,
                sessionKey
            );
            testsLogger(DEBUGLEVEL.VERBOSE, `requestAttestAndUsage = ${requestAttestAndUsage}`);
        } catch (e) {
            testsLogger(DEBUGLEVEL.LOW, e);
            throw new Error('requestAttestAndUsage failed');
        }

        // if no Errors then its OK
        expect(1).toBe(1);
    })

    test('constructAttest (js-generated request-attest-and-usage)', async () => {

        let attestRes = Authenticator.constructAttest(attestorKey,'AlphaWallet', 60*60*1000, requestAttestAndUsage, ATTESTOR_DOMAIN);

        // if no Errors then its OK
        expect(1).toBe(1);
    })

    test('verify-usage(js-generated request-attest-and-usage)', async () => {
        let res;
        try {
            res = await Authenticator.verifyUsage(
                // useAttestRes,
                requestAttestAndUsage,
                attestorPubKey,
                sessionMessage,
                ATTESTOR_DOMAIN,
                sessionSignature);
            testsLogger(DEBUGLEVEL.VERBOSE, `verifyUsage result = ${res}`);
        } catch (e) {
            testsLogger(DEBUGLEVEL.LOW, e);
            throw new Error('verifyUsage failed');
        }
        expect(res).toBe("SUCCESSFULLY validated usage request!");

    })

})






