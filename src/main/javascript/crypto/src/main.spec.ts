/**
 * @jest-environment jsdom
 */

import {
    bnToUint8,
    hexStringToUint8,
    stringToArray,
    uint8arrayToBase64,
    uint8tohex,
    testsLogger, base64ToUint8array
} from './libs/utils';
import {readFileSync} from "fs";
import {KeyPair} from "./libs/KeyPair";
import {Authenticator} from "./Authenticator";
import {Asn1Der} from "./libs/DerUtility";
import {DEBUGLEVEL} from "./config";

import {Ticket} from "./Ticket";
import {IdentifierAttestation} from "./libs/IdentifierAttestation";
import {SignedIdentifierAttestation} from "./libs/SignedIdentifierAttestation";
import {ERC721Token} from "./libs/ERC721Token";
import {NFTAttestation} from "./libs/NFTAttestation";
import {SignedNFTAttestation} from "./libs/SignedNFTAttestation";
import {Signature} from "./libs/Signature";
import {RawSignature} from "./libs/RawSignature";
import {PersonalSignature} from "./libs/PersonalSignature";

const querystring = require('querystring');
import {Issuer} from "./libs/Issuer";
import { AttestedObject } from './libs/AttestedObject';
import { AttestableObject } from './libs/AttestableObject';
import { UseToken } from './asn1/shemas/UseToken';
import subtle from "./safe-connect/SubtleCryptoShim";
import {EthereumAddressAttestation} from "./safe-connect/EthereumAddressAttestation";
import {EthereumKeyLinkingAttestation} from "./safe-connect/EthereumKeyLinkingAttestation";
const url = require('url');

let EC = require("elliptic");

const PREFIX_PATH = '../../../../build/test-results/';

let useAttestRes: string,
    sessionKey: KeyPair,
    session2Key: KeyPair,
    userKey: KeyPair,
    userPubKey: KeyPair,
    attestorPubKey: KeyPair,
    attestorKey: KeyPair,

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


describe("SignedIdentifierAttestation", () => {
    let subjectKeys = userKey;
    let nfts:ERC721Token[];
    let signedIdentifierAtt: SignedIdentifierAttestation;
    let signedNftAttestation: SignedNFTAttestation;
    let nftAtt:NFTAttestation;

    test('setup', () => {

        let att:IdentifierAttestation = IdentifierAttestation.fromLabelAndUrl("205521676", "https://twitter.com/zhangweiwu", subjectKeys);
        expect(att.checkValidity()).toBe(true);
        signedIdentifierAtt = SignedIdentifierAttestation.fromData(att, attestorKey);
        nfts = [
            ERC721Token.fromStrings("0xa567f5A165545Fa2639bBdA79991F105EADF8522", "25"),
            ERC721Token.fromStrings("0xa567f5A165545Fa2639bBdA79991F105EADF8522", "26")
        ];
        testsLogger(DEBUGLEVEL.MEDIUM , "SubjectPublicKey's Fingerprint (summarised as Ethereum address):\n" + userPubKey.getPublicKeyAsHexStr());

        expect(signedIdentifierAtt.verify()).toBe(true);
        expect(signedIdentifierAtt.checkValidity()).toBe(true);

    })

    test('testNFTAttestation', () => {

        nftAtt = NFTAttestation.fromAttAndTokens(signedIdentifierAtt, nfts);
        //construct SignedNFTAttestation using subject key
        signedNftAttestation = SignedNFTAttestation.fromAtt(nftAtt, subjectKeys);

        expect(signedNftAttestation.verify()).toBe(true);
        expect(signedNftAttestation.checkValidity()).toBe(true);

        //Extract the Ethereum signature
        let sig:Signature = signedNftAttestation.getSignature();

        // testsLogger(DEBUGLEVEL.LOW, nftAtt.getDerEncoding());
        let realSignedNFTAtt =  "MIICkjCCAj8wggIdMIIByqADAgETAgEBMAkGByqGSM49BAIwGTEXMBUGA1UEAwwOYXR0ZXN0YXRpb24uaWQwIhgPMjAyMTExMDMyMTM0NDFaGA85OTk5MTIzMTIzNTk1OVowPzE9MDsGCSsGAQQBgXoBOQwuaHR0cHM6Ly90d2l0dGVyLmNvbS9PbGVoUnYgMTM4NzgwNjM2NzY2NzMzOTI3NTCCATMwgewGByqGSM49AgEwgeACAQEwLAYHKoZIzj0BAQIhAP////////////////////////////////////7///wvMEQEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwRBBHm+Zn753LusVaBilc6HCwcCm/zbLc4o2VnygVsW+BeYSDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj/sQ1LgCIQD////////////////////+uq7c5q9IoDu/0l6M0DZBQQIBAQNCAAQvGW7DOtBMY5j+ju8ahNiFU5dkG7TLu89XbjuqNMUWpRsurGsgHdJJULZRPL2F9r0aEbe61RE0PZ2t7Msw9yZCMAkGByqGSM49BAIDQgCT5mb1dcBRLlxJa3RLi25KIjWMAErnZDIJ1Wc4dJrFkSh/TU5D9cIS0lbOoAUfEFvJB39k0aqHuIwNLM8Xe+BBGzAcMBoEFAAAgMCSZPVRYLcZ1nAEJLh3yNl3BAIBDTAJBgcqhkjOPQQCA0IAijX0yxUsm53EIG35ffgGDGfmd34ENfSGVNcK8EVllTsC8+WjmpBykKJsFDH++zgY14MuHNBUB2/ZTt3PpTIKSBw=";

        //generate NFTAttestation from the NFTAttestation bytes

        let nftAttestation2:NFTAttestation = NFTAttestation.fromDer(hexStringToUint8(nftAtt.getDerEncoding()), attestorPubKey);

        //check recovered signed attestation within the wrapping
        expect(nftAttestation2.verify()).toBe(true);

        //Generate SignedNFTAttestation using the reconstructed NFTAttestation and the extracted Ethereum signature

        let signedNFTAttestation2:SignedNFTAttestation = SignedNFTAttestation.fromAttAndSign(nftAttestation2, sig);
        expect(signedNFTAttestation2.checkValidity()).toBe(true);
        expect(signedNftAttestation.checkValidity()).toBe(true);

        expect(signedNFTAttestation2.getUnsignedAttestation().getDerEncoding()).toEqual(nftAtt.getDerEncoding());
        expect(signedNFTAttestation2.getDerEncoding()).toEqual(signedNftAttestation.getDerEncoding());

    })

    test('consistentEncoding', () => {
        let decodedNFTAtt:SignedNFTAttestation = SignedNFTAttestation.fromASN(hexStringToUint8(signedNftAttestation.getDerEncoding()), attestorPubKey);

        expect(decodedNFTAtt.verify()).toBe(true);
        expect(decodedNFTAtt.checkValidity()).toBe(true);

        expect(signedNftAttestation.getDerEncoding()).toEqual(decodedNFTAtt.getDerEncoding());
    })


    test('testGetters', () => {
        expect(signedNftAttestation.getAttestationVerificationKey().getAddress()).toBe(subjectKeys.getAddress());
        expect(nftAtt.getTokens()).toEqual(nfts);
    })


    test('testPublicAttestation', () => {
        expect(signedIdentifierAtt.checkValidity()).toBe(true);
        expect(signedIdentifierAtt.verify()).toBe(true);
    })

    test('defaultSigningVersion', () => {
        let newSignedNftAtt:SignedNFTAttestation = SignedNFTAttestation.fromAttAndSign(signedNftAttestation.getUnsignedAttestation(), signedNftAttestation.getSignature());
        expect(signedNftAttestation.getDerEncoding() == newSignedNftAtt.getDerEncoding()).toBe(true);
        expect(newSignedNftAtt.verify()).toBe(true);
        expect(newSignedNftAtt.checkValidity()).toBe(true);
        let otherConstructor:SignedNFTAttestation = SignedNFTAttestation.fromASN(hexStringToUint8(newSignedNftAtt.getDerEncoding()), attestorPubKey);
        expect(signedNftAttestation.getDerEncoding() == otherConstructor.getDerEncoding()).toBe(true);
        expect(otherConstructor.verify()).toBe(true);
        expect(otherConstructor.checkValidity()).toBe(true);
    })

    test('oldVersionSigning', () => {
        let newSignedNftAtt:SignedNFTAttestation = SignedNFTAttestation.fromAttAndSign(signedNftAttestation.getUnsignedAttestation(), signedNftAttestation.getSignature());
        expect(signedNftAttestation.getDerEncoding() == newSignedNftAtt.getDerEncoding()).toBe(true);
        expect(newSignedNftAtt.verify()).toBe(true);
        expect(newSignedNftAtt.checkValidity()).toBe(true);
        let otherConstructor:SignedNFTAttestation = SignedNFTAttestation.fromASN(hexStringToUint8(newSignedNftAtt.getDerEncoding()), attestorPubKey);
        expect(signedNftAttestation.getDerEncoding() == otherConstructor.getDerEncoding()).toBe(true);
        expect(otherConstructor.verify()).toBe(true);
        expect(otherConstructor.checkValidity()).toBe(true);
    })

    test('unknownVersion', () => {
        expect( ()=>{SignedNFTAttestation.fromAttAndVer(nftAtt, subjectKeys, 42)}).toThrowError();
    })

    test('unknownVersionOtherConstructor', () => {
        let rawSignature:RawSignature = new RawSignature();
        rawSignature.fromMessage(subjectKeys, hexStringToUint8(nftAtt.getDerEncoding()));
        let rawSig: Signature = rawSignature as Signature;
        expect( ()=>{SignedNFTAttestation.fromAttAndSign(nftAtt, rawSig)}).toThrowError();
    })

    test('badSignatureVersion', () => {
        expect(()=>{
            signedNftAttestation.makeSignature(Uint8Array.from([42]), 42)
        } ).toThrowError();
    })

    test('signingVersion1Included', () => {
        let urlEncodedSignedNftAtt:string = "MIICqTCCAlMwggIXMIIBxKADAgETAgEBMAkGByqGSM49BAIwGTEXMBUGA1UEAwwOYXR0ZXN0YXRpb24uaWQwIhgPMjAyMTExMDkxNjIwMThaGA85OTk5MTIzMTIyNTk1OVowOTE3MDUGCSsGAQQBgXoBOQwoaHR0cHM6Ly90d2l0dGVyLmNvbS96aGFuZ3dlaXd1IDIwNTUyMTY3NjCCATMwgewGByqGSM49AgEwgeACAQEwLAYHKoZIzj0BAQIhAP____________________________________7___wvMEQEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwRBBHm-Zn753LusVaBilc6HCwcCm_zbLc4o2VnygVsW-BeYSDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj_sQ1LgCIQD____________________-uq7c5q9IoDu_0l6M0DZBQQIBAQNCAASVDHwL7SPDysXMMbu5qtm7VTI4eIJnCsKxzfB5mrDrx2TCZ_cE6P3aB5arg5ek0hAQJNJMTv_2lbOkF_LtDkjNMAkGByqGSM49BAIDQgD8Wu2eGeRW1GNFxOk5Srdn4E968ML7MUINj55zBqhuOhUWmosV5d4VsarkmpCmlwAXxvIpt7UcFP4cK8QuwH89GzA2MBkEFKVn9aFlVF-iY5u9p5mR8QXq34UiBAEZMBkEFKVn9aFlVF-iY5u9p5mR8QXq34UiBAEaAgEBMAkGByqGSM49BAIDQgCrpY0RQ3LNfJd6YgYEC-etEU_oJKUAA6WP0TRfZITeQVNNm21BOFQc-iiXs053UcSy1y29tbUPt1wp4VRU8Qu4Gw==";

        // java tests generate keys in different order, so current key subjectKey = attestorKey
        signedNftAttestation = SignedNFTAttestation.fromASN(base64ToUint8array(urlEncodedSignedNftAtt), subjectKeys);
        let newSignedNftAtt:SignedNFTAttestation = SignedNFTAttestation.fromAttAndSign(signedNftAttestation.getUnsignedAttestation(), signedNftAttestation.getSignature());
        expect(newSignedNftAtt.verify()).toBe(true);
        expect(newSignedNftAtt.checkValidity()).toBe(true);
    })

    test('badSignature', () => {
        let s = new PersonalSignature();
        s.fromMessage(subjectKeys, Uint8Array.from([1,2,3,4]));
        let wrongSignature: Signature = s as Signature;
        expect(()=>{
            SignedNFTAttestation.fromAttAndSign(nftAtt, wrongSignature);
        } ).toThrowError();
    })

    test('badSigningKey', () => {
        expect(()=>{
            SignedNFTAttestation.fromAtt(nftAtt, sessionKey);
        } ).toThrowError();
    })


});

describe("SignatureTest ", () => {

})

describe("MagicLink reader", () => {
    test('Decode Magic Link from Java Build', async () => {
        if (magicLink.substring(0,1) == "?") magicLink = magicLink.substring(1);
        let params = querystring.parse(magicLink);

        let senderKey = KeyPair.publicFromBase64orPEM(magicLinkPublicPEM);
        let res;
        try {
            res = await Issuer.validateTicket(params.ticket, params.pok, params.mail, senderKey);
        } catch(e){
            testsLogger(DEBUGLEVEL.LOW,"Issuer.validateTicket failed");
            testsLogger(DEBUGLEVEL.LOW,e);
        }
        expect(res).toBe(true);
    });

    test('Encode/Decode Magic Link from JS', async () => {
        let res;
        let senderKey;
        try {
            
            senderKey = KeyPair.privateFromKeyDataPEM(magicLinkPrivatePEM);

            res = await Issuer.constructTicket("mail@mail.com", "6", "222", 9, senderKey);
            testsLogger(DEBUGLEVEL.VERBOSE, `Signed ticket = ${res}`);
        } catch (e) {
            testsLogger(DEBUGLEVEL.LOW, e);
            throw new Error('verifyUsage failed');
        }

        try {
            
            res = await Issuer.constructTicket("mail@mail.com", "6", "test", 9, senderKey);
            testsLogger(DEBUGLEVEL.VERBOSE, `Signed ticket = ${res}`);
        } catch (e) {
            testsLogger(DEBUGLEVEL.LOW, e);
            throw new Error('verifyUsage failed');
        }
        expect(1).toBe(1);

    })

    test('Verify Ticket', async () => {
        let magicLink;
        let senderKey;
        try {
            
            senderKey = KeyPair.privateFromKeyDataPEM(magicLinkPrivatePEM);

            magicLink = await Issuer.constructTicket("mail@mail.com", "6", "222", 9, senderKey);
            testsLogger(DEBUGLEVEL.VERBOSE, `Signed ticket = ${magicLink}`);
        } catch (e) {
            testsLogger(DEBUGLEVEL.LOW, e);
            throw new Error('construct Ticket failed');
        }


        try {

            let params = new URLSearchParams(magicLink);
			let ticketOnly = params.get("ticket");
            
            let res = Authenticator.validateTicket(ticketOnly, "6", magicLinkPublicPEM);

            testsLogger(DEBUGLEVEL.VERBOSE, res);
            expect(res).toStrictEqual({
                valid: true,
                ticketId: '222',
                ticketClass: 9,
            });
        } catch (e) {
            testsLogger(DEBUGLEVEL.LOW, e);
            throw new Error('verifyUsage failed');
        }

    })





});

describe("magicLink", () => {

    test('Session key sign+verify message', async () => {
        if (magicLink.substring(0,1) == "?") magicLink = magicLink.substring(1);
        let str = querystring.parse(magicLink);
        let ticket = new Ticket();
        ticket.fromBytes(base64ToUint8array(str.ticket),{'6' : KeyPair.publicFromBase64orPEM( magicLinkPublicPEM) });
        expect(ticket.verify()).toBe(true);

    })
})

/*
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
*/

describe("Attestation request/construct", () => {

    test("Construct Attestation(from ready attest request)", () => {

        let ATTESTOR_DOMAIN = "http://wwww.attestation.id"
        let usageValue = "Creating email attestation";
        let attestationResult = Authenticator.constructAttest(attestorKey, 'AlphaWallet', 60*60*1000, attestationRequestJson, ATTESTOR_DOMAIN, usageValue);

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

describe("read public key", () => {

    const keyFile1 = '-----BEGIN PUBLIC KEY-----\n' +
    'MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEQKYTwFMIzSq1QVxoRKoOZXLQ9mUhce8M\n' +
    'dIzvJx3unbpR3m3TiuWKZKTP4/XCPnS56d1tAhjM43hHjHbZ0k3RKQ==\n' +
    '-----END PUBLIC KEY-----';
    let addr1 = "0x4F3CEF0C905EB4EDF9C4FFC71C4C4B06417BAC3E";
    const keyFile2 = 'MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEOt9mWLpQVOxiOvswFK4GGI0oOZ2GqS2Q6ec0AWIeuVoCuTD+atppPvjMgNLg9qQzJxsDW3zLxnOPFWO/Decnag==';
    let addr2 = "0x17C0B3B51A75F1A001F255A7CAD4FA45529CAC20";
 				

    test('read 2 keys', async () => {
        let key1 = Authenticator.decodePublicKey(keyFile1);
        expect(key1.getAddress().toLocaleLowerCase()).toBe(addr1.toLocaleLowerCase());
        
        let key2 = Authenticator.decodePublicKey(keyFile2);
        expect(key2.getAddress().toLocaleLowerCase()).toBe(addr2.toLocaleLowerCase());
    })
})

describe("read attested object", () => {

    const base64senderPublicKeys = { 
        "AttestationDAO" : 'MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEOt9mWLpQVOxiOvswFK4GGI0oOZ2GqS2Q6ec0AWIeuVoCuTD+atppPvjMgNLg9qQzJxsDW3zLxnOPFWO/Decnag=='
    }
    const base64attestorPubKey = "MIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA/////////////////////////////////////v///C8wRAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHBEEEeb5mfvncu6xVoGKVzocLBwKb/NstzijZWfKBWxb4F5hIOtp3JqPEZV2k+/wOEQio/Re0SKaFVBmcR9CP+xDUuAIhAP////////////////////66rtzmr0igO7/SXozQNkFBAgEBA0IABL+y43T1OJFScEep69/yTqpqnV/jzONz9Sp4TEHyAJ7IPN9+GHweCX1hT4OFxt152sBN3jJc1s0Ymzd8pNGZNoQ="

    // one month attestation up to 15.05.2022
    const attestation = "3082036130819f30590c0e4174746573746174696f6e44414f02010502010004410403457b7a84a81a9a9e1d52e5b436389105fede62e0cb7211e6db82519cf5b67a14517f3d4288eb9adb8ed957f8e887d1d91bc971cd762994775f4169af789b50034200ca7468483c53f2032e82c8a288dc84ed57a7ebbd5537413d7dd6a4c0958ad7a101ac4f5970feac7861ff62b8e2767428fbc5a353def37d3e9ac44754a7febaa31c30820252308201ffa0030201120208233635fe3b69138e300906072a8648ce3d040230163114301206035504030c0b416c70686157616c6c6574302e180f32303232303531353031343632335a020462805b6f180f32303232303631343031343632335a020462a7e86f300b3109300706035504030c00308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f3044042000000000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000000704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101034200042f196ec33ad04c6398fe8eef1a84d8855397641bb4cbbbcf576e3baa34c516a51b2eac6b201dd24950b6513cbd85f6bd1a11b7bad511343d9dadeccb30f72642a35730553053060b2b060104018b3a737901280101ff0441040ab633ddd62c1742977ef34d20dbd75d1ad689b34e1c42a41d696a40c2d2fe851dab5e779ddc8e86c2a7f9e582d3e9204972a6a62d34439d25f22de3bafbec03300906072a8648ce3d04020342008c9d1ed83f9d5eae300ddee572de7c1267700be138b9eaa5a088511aa2ad87f164559c5b7e91f3b83031c19f08e3cdfe37f9258e9311413151c163af2482fa7d1c30670420190beb6bcdf48a2f6cc125a162ef0480b7a6343ac59babf245d877dccc3361e004410405396b26903f8574227c4c240015beb1ed2619e8c88564aeefef8f32527925e52966d8a4c97e2ab4a15c8d0cba230340437feb168af0ff8d46fe2da6a5ece16a0400";

    test('validate attestation', async () => {

        let attestor = KeyPair.publicFromBase64orPEM(base64attestorPubKey);
        let issuers = {"AttestationDAO" : KeyPair.publicFromBase64orPEM(base64senderPublicKeys.AttestationDAO)}

        let subj = "0x2F21dC12dd43bd15b86643332041ab97010357D7";

        let attest = AttestedObject.fromBytes(
            hexStringToUint8(attestation),
            UseToken,
            attestor,
            Ticket,
            issuers
            );
        
        expect(attest.checkValidity(subj)).toBe(true);

    })
});

describe("Safe Connect", () => {

    const KEY_ALGORITHM = "RSASSA-PKCS1-v1_5";
    const ATTESTOR_PRIV_KEY = "7411181bdb51a24edd197bacda369830b1c89bbf872a4c2babbdd2e94f25d3b5";
    const NFT_ADDRESS = "";
    const LINKED_ADDRESS = "";

    const attestorKeys = KeyPair.fromPrivateUint8(hexStringToUint8(ATTESTOR_PRIV_KEY), 'secp256k1');

    async function createAttestation(nftWallet: string, linkedWallet: string, validity:number = 3600, validFrom?: number){

        const attestHoldingKey = await subtle.generateKey(
            {
                name: KEY_ALGORITHM,
                modulusLength: 1024,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                hash: {name: "SHA-256"}
            },
            false,
            ["sign", "verify"]
        );

        const holdingPubKey = new Uint8Array(await subtle.exportKey("spki", attestHoldingKey.publicKey));

        const attestation = new EthereumAddressAttestation();

        attestation.create(holdingPubKey, nftWallet, attestorKeys, validity, validFrom);
        const base64Attest = attestation.getBase64();

        const linkAttest = new EthereumKeyLinkingAttestation();

        linkAttest.create(base64Attest, linkedWallet, validity, validFrom);
        await linkAttest.sign(attestHoldingKey.privateKey);

        return linkAttest;
    }

    let base64Attest: string;

    test("Create attestation", async () => {

        let attestation = await createAttestation(NFT_ADDRESS, LINKED_ADDRESS);
        base64Attest = attestation.getBase64();

        expect(attestation).not.toBe(EthereumKeyLinkingAttestation);
    });

    test("Parse & verify attestation", async () => {

        const linkAttest = new EthereumKeyLinkingAttestation();

        linkAttest.fromBase64(base64Attest);

        await expect(async() => { await linkAttest.verify(attestorKeys) }).not.toThrowError();
    });

    test("Expired attestation should not validate", async () => {

        let linkAttest = await createAttestation(NFT_ADDRESS, LINKED_ADDRESS, 3600, Math.round(Date.now() / 1000) - 7200);

        let err;

        try {
            await linkAttest.verify(attestorKeys);
        } catch (e){
            err = e;
        }

        expect(err.message).toBe("Linked attestation has expired");
    });

    test("Not yet valid attestation should not validate", async () => {

        let linkAttest = await createAttestation(NFT_ADDRESS, LINKED_ADDRESS, 3600, Math.round(Date.now() / 1000) + 3600);

        let err;

        try {
            await linkAttest.verify(attestorKeys);
        } catch (e){
            err = e;
        }

        expect(err.message).toBe("Linked attestation is not yet valid");
    });
});


