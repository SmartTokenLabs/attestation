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
import { UseToken } from './asn1/shemas/UseToken';
import subtle from "./safe-connect/SubtleCryptoShim";
import {EthereumAddressAttestation} from "./safe-connect/EthereumAddressAttestation";
import {EthereumKeyLinkingAttestation} from "./safe-connect/EthereumKeyLinkingAttestation";
import {NFTOwnershipAttestation} from "./safe-connect/NFTOwnershipAttestation";

import {EasTicketAttestation} from "./eas/EasTicketAttestation";
import {ethers} from "ethers";
import {EasZkProof} from "./eas/EasZkProof";
import {ATTESTATION_TYPE} from "./libs/interfaces";
import {AttestationCrypto} from "./libs/AttestationCrypto";

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
            ticketOnly = ticketOnly ?? "";
            
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
        attestationRequestJson = attestJson ?? "";
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
            testsLogger(DEBUGLEVEL.LOW, "Authenticator.verifyUsage error: ", e);
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
                userKey) || "";
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
            ) || "";
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

describe("read attested object", () => {
    const ticketPubPEM = readFileSync(PREFIX_PATH + 'ticket-issuer-key.pem', 'utf8');
    let ticketPubKey = KeyPair.publicFromBase64orPEM(ticketPubPEM);
   
    const issuerPublicKeys = { 
        "hejJ" : ticketPubKey
    }

    const attestorPubPEM = readFileSync(PREFIX_PATH + 'att-issuer-key.pem', 'utf8');
    let attestorPubKey = KeyPair.publicFromBase64orPEM(attestorPubPEM);

    let attestation = readFileSync(PREFIX_PATH + 'attested-ticket.txt', 'utf8');

    test('validate attestation', async () => {

        let subj = "0x7A181CB7250776E16783F9D3C9166DE0F95AB283";

        let attest = AttestedObject.fromBytes(
            base64ToUint8array(attestation),
            UseToken,
            attestorPubKey,
            Ticket,
            issuerPublicKeys
            );
        // console.log(attest);
        expect(attest.checkValidity(subj)).toBe(true);

    })
});

describe("Safe Connect", () => {

    const KEY_ALGORITHM = "RSASSA-PKCS1-v1_5";
    const ATTESTOR_PRIV_KEY = "7411181bdb51a24edd197bacda369830b1c89bbf872a4c2babbdd2e94f25d3b5";
    const NFT_ADDRESS = "0xe761eb6e829de49deab008120733c1e35acf77db";
    const LINKED_ADDRESS = "0x2F21dC12dd43bd15b86643332041ab97010357D7";

    const attestorKeys = KeyPair.fromPrivateUint8(hexStringToUint8(ATTESTOR_PRIV_KEY), 'secp256k1');

    async function createAttestation(nftWalletOrTokens: string | [{address: string, chainId: number, tokenIds?: bigint[]}], linkedWallet: string, validity:number = 3600, context?: Uint8Array, validFrom?: number){

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

        let base64Attest;

        if (typeof nftWalletOrTokens === "string"){
            const attestation = new EthereumAddressAttestation();
            attestation.create(holdingPubKey, nftWalletOrTokens, attestorKeys, validity, context, validFrom);
            base64Attest = attestation.getBase64();
        } else {
            const attestation = new NFTOwnershipAttestation();
            attestation.create(holdingPubKey, nftWalletOrTokens, attestorKeys, validity, context, validFrom);
            base64Attest = attestation.getBase64();
        }

        const linkAttest = new EthereumKeyLinkingAttestation();

        linkAttest.create(base64Attest, linkedWallet, validity, undefined, validFrom);
        // linkAttest.create(base64Attest, linkedWallet, validity, null, validFrom);
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

        await expect(await linkAttest.verify(attestorKeys)).not.toThrow;
    });

    test("Expired attestation should not validate", async () => {

        let linkAttest = await createAttestation(NFT_ADDRESS, LINKED_ADDRESS, 3600, undefined, Math.round(Date.now() / 1000) - 7200);
        // let linkAttest = await createAttestation(NFT_ADDRESS, LINKED_ADDRESS, 3600, null, Math.round(Date.now() / 1000) - 7200);

        let err = "";

        try {
            await linkAttest.verify(attestorKeys);
        } catch (e){
            if (e instanceof Error) err = e.message
        }

        expect(err).toBe("Linked attestation has expired");
    });

    test("Not yet valid attestation should not validate", async () => {

        let linkAttest = await createAttestation(NFT_ADDRESS, LINKED_ADDRESS, 3600, undefined, Math.round(Date.now() / 1000) + 3600);
        // let linkAttest = await createAttestation(NFT_ADDRESS, LINKED_ADDRESS, 3600, null, Math.round(Date.now() / 1000) + 3600);

        let err = "";

        try {
            await linkAttest.verify(attestorKeys);
        } catch (e){
            if (e instanceof Error) err = e.message
        }

        expect(err).toBe("Linked attestation is not yet valid");
    });

    test("NFT attestation should be valid", async () => {

        let linkAttest = await createAttestation([{address: "0x3d8a0fB32b0F586FdC10447c22F477979dc526ec", chainId: 4, tokenIds: [1n, 2n]}], LINKED_ADDRESS, 3600);

        await expect(await linkAttest.verify(attestorKeys)).not.toThrow;
    });
    
    test("safe-connect mvp address attestation", async () => {
        const keyLinkingAttEcEcBase64 = readFileSync(PREFIX_PATH + 'signedEthereumKeyLinkingAttestation-mvp-address.txt', 'utf8');
        
        let keyLinkingAtt = new EthereumKeyLinkingAttestation();
        keyLinkingAtt.fromBytes(base64ToUint8array(keyLinkingAttEcEcBase64));
        await expect(await keyLinkingAtt.verify(safeconnectKey)).not.toThrow;
    });

    test("test safe-connect mvp nft attestation", async () => {
        const nftLinkingAttEcEcBase64 = readFileSync(PREFIX_PATH + 'signedEthereumKeyLinkingAttestation-mvp-nft.txt', 'utf8');
        
        let keyLinkingAtt = new EthereumKeyLinkingAttestation();
        keyLinkingAtt.fromBytes(base64ToUint8array(nftLinkingAttEcEcBase64));
        await expect(await keyLinkingAtt.verify(safeconnectKey)).not.toThrow;
    });

    // TODO implement once context is supports, i.e. this issue is completed https://smarttokenlabs.atlassian.net/browse/TKN-276
// test("safe-connect with context", async () => {
//     const issuerPubKeyPem = readFileSync(PREFIX_PATH + 'key-ec.txt', 'utf8');
//     let issuerPubKey = KeyPair.publicFromBase64orPEM(issuerPubKeyPem);

//     const keyLinkingAttEcEcBase64 = readFileSync(PREFIX_PATH + 'signedEthereumKeyLinkingAttestation-nft-subject-rsa-issuer-ec.txt', 'utf8');
    
//     let keyLinkingAtt = new EthereumKeyLinkingAttestation();

//     test('validate key linking attestation', async () => {
//         keyLinkingAtt.fromBytes(base64ToUint8array(keyLinkingAttEcEcBase64));
//         await expect(await keyLinkingAtt.verify(issuerPubKey)).not.toThrow;
//     });
// })

    test("Write test data for safeconnect java", async () => {
        const fs = require('fs');
        let attestation = await createAttestation(NFT_ADDRESS, LINKED_ADDRESS);
         //console.log(attestation.getAttestation().ethereumKeyLinkingAttestation.linkedAttestation.attestation.ethereumAddress);
        fs.writeFileSync(PREFIX_PATH + 'signedEthereumKeyLinkingAttestation-mvp-address-js.txt', attestation.getBase64());
        fs.writeFileSync(PREFIX_PATH + 'key-ec-js.txt', attestorKeys.getAsnDerPublic());
        // Test file reading
        const readAttestationBase64 = readFileSync(PREFIX_PATH + 'signedEthereumKeyLinkingAttestation-mvp-address-js.txt', 'utf8');
        let readAttestation = new EthereumKeyLinkingAttestation();
        readAttestation.fromBytes(base64ToUint8array(readAttestationBase64));
        await expect(await readAttestation.verify(attestorKeys)).not.toThrow;
    });
});

describe("EAS Ticket Attestation", () => {

    const SEPOLIA_RPC = 'https://rpc.sepolia.org/'

    const EAS_CONFIG = {
        address: '0xC2679fBD37d54388Ce493F1DB75320D236e1815e',
        version: '0.26',
        chainId: 11155111,
    }

    const EAS_TICKET_SCHEMA = {
        fields: [
            { name: 'devconId', type: 'string' },
            { name: 'ticketIdString', type: 'string' },
            { name: 'ticketClass', type: 'uint8' },
            { name: 'commitment', type: 'bytes', isCommitment: true },
        ],
    }

    const issuerPrivKey = KeyPair.privateFromPEM('MIICSwIBADCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA/////////////////////////////////////v///C8wRAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHBEEEeb5mfvncu6xVoGKVzocLBwKb/NstzijZWfKBWxb4F5hIOtp3JqPEZV2k+/wOEQio/Re0SKaFVBmcR9CP+xDUuAIhAP////////////////////66rtzmr0igO7/SXozQNkFBAgEBBIIBVTCCAVECAQEEIM/T+SzcXcdtcNIqo6ck0nJTYzKL5ywYBFNSpI7R8AuBoIHjMIHgAgEBMCwGByqGSM49AQECIQD////////////////////////////////////+///8LzBEBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcEQQR5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmEg62ncmo8RlXaT7/A4RCKj9F7RIpoVUGZxH0I/7ENS4AiEA/////////////////////rqu3OavSKA7v9JejNA2QUECAQGhRANCAARjMR62qoIK9pHk17MyHHIU42Ix+Vl6Q2gTmIF72vNpinBpyoBkTkV0pnI1jdrLlAjJC0I91DZWQhVhddMCK65c');
    const provider = new ethers.providers.JsonRpcProvider(SEPOLIA_RPC)
    const wallet = new ethers.Wallet(issuerPrivKey.getPrivateAsHexString(), provider)
    const attestationManager = new EasTicketAttestation(EAS_TICKET_SCHEMA, {
        EASconfig: EAS_CONFIG,
        signer: wallet
    }, {11155111: SEPOLIA_RPC});
    const pubKeyConfig = {"6": issuerPrivKey};

    async function createAttestation(validity?: {from: number, to: number}){

        return await attestationManager.createEasAttestation({
            devconId: '6',
            ticketIdString: '12345',
            ticketClass: 2,
            commitment: email,
        }, {
            validity
        });
    }

    function getIdAttest(email: string, idSecret: bigint){
        let att:IdentifierAttestation = IdentifierAttestation.fromData(email, ATTESTATION_TYPE.mail, userKey, idSecret);
        att.setSerialNumber(1);
        att.setIssuer("CN=attestation.id");
        expect(att.checkValidity()).toBe(true);
        return hexStringToBase64(SignedIdentifierAttestation.fromData(att, attestorKey).getDerEncoding());
    }

    test("Create EAS Devcon ticket", async () => {
        await createAttestation();
    });

    test("Load from URL encoded and validate", async () => {
        await createAttestation();

        const encoded = attestationManager.getEncoded();

        attestationManager.loadFromEncoded(encoded, pubKeyConfig);
        await attestationManager.validateEasAttestation();
    });

    test("Load from ASN encoded and validate", async () => {
        await createAttestation();

        const encoded = attestationManager.getAsnEncoded(false);

        attestationManager.loadAsnEncoded(encoded, pubKeyConfig, false);
        await attestationManager.validateEasAttestation();


        const encodedCompressed = attestationManager.getAsnEncoded(true);

        attestationManager.loadAsnEncoded(encodedCompressed, pubKeyConfig, true);
        await attestationManager.validateEasAttestation();
    });

    test("Test wrong conference ID", async () => {
        await createAttestation();

        const easData = attestationManager.getEasJson();

        expect(() => attestationManager.loadEasAttestation(easData.sig, {'2': pubKeyConfig['6']})).toThrowError('No key set for conference ID 6');
    });

    test("Test bad signature", async () => {
        await createAttestation();

        const easData = attestationManager.getEasJson();

        attestationManager.loadEasAttestation(easData.sig, {'6': KeyPair.fromPublicHex('0463311eb6aa820af691e4d7b3321c7214e36231f9597a43681398817bdaf3698a7069ca80644e4574a672358ddacb9408c90b423dd4365642156175d3022bae5d')});

        await expect(attestationManager.validateEasAttestation()).rejects.toThrowError('Ticket signature is invalid');
    });

    test("Test expired", async () => {
        await createAttestation({from: 0, to: Math.round(Date.now()/ 1000) - 360})

        const easData = attestationManager.getEasJson();

        attestationManager.loadEasAttestation(easData.sig, pubKeyConfig);
        await expect(attestationManager.validateEasAttestation()).rejects.toThrowError('Attestation has expired.');
    });

    test("Test not yet valid", async () => {
        await createAttestation({from: Math.round(Date.now()/ 1000) + 360, to: 0})

        const easData = attestationManager.getEasJson();

        attestationManager.loadEasAttestation(easData.sig, pubKeyConfig);
        await expect(attestationManager.validateEasAttestation()).rejects.toThrowError('Attestation not yet valid.');
    });

    test("Ensure secrets are difference for each generated attestation", async () => {
        const attest1 = await createAttestation();
        const attest2 = await createAttestation();

        expect(attest1.secret).not.toEqual(attest2.secret);
    });

    // TODO: Revocation tests with local EVM network

    test("ZKProof create & validate", async () => {

        await createAttestation()

        const ticketBase64 = attestationManager.getEncoded();
        const ticketSecret = attestationManager.getEasJson().secret;

        const easZkProof = new EasZkProof(EAS_TICKET_SCHEMA, {11155111: SEPOLIA_RPC});

        // Generate identifier attestation
        const idSecret = (new AttestationCrypto()).makeSecret()
        const idBase64 = getIdAttest(email, idSecret);
        const attestationIdPublic = hexStringToBase64(attestorKey.getAsnDerPublic());

        // Create ZKProof attestation
        const base64UseTicketAttestation = easZkProof.getUseTicket(BigInt(<string>ticketSecret), BigInt(idSecret), ticketBase64, idBase64, attestationIdPublic, pubKeyConfig);

        await easZkProof.validateUseTicket(base64UseTicketAttestation, attestationIdPublic, pubKeyConfig, userKey.getAddress());

    });

    test("ZKProof wrong commitment value", async () => {

        await createAttestation()

        const ticketBase64 = attestationManager.getEncoded();
        const ticketSecret = attestationManager.getEasJson().secret;

        const easZkProof = new EasZkProof(EAS_TICKET_SCHEMA, {11155111: SEPOLIA_RPC});

        // Generate identifier attestation
        const idSecret = (new AttestationCrypto()).makeSecret()
        const idBase64 = getIdAttest("wrongemail@test.com", idSecret);
        const attestationIdPublic = hexStringToBase64(attestorKey.getAsnDerPublic());

        // Create ZKProof attestation
        expect(() => easZkProof.getUseTicket(BigInt(<string>ticketSecret), BigInt(idSecret), ticketBase64, idBase64, attestationIdPublic, pubKeyConfig)).toThrowError("The redeem proof did not verify");
    });

});
