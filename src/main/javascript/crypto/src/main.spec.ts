import {base64ToUint8array, uint8toBuffer, uint8tohex} from './libs/utils';
import {readFileSync} from "fs";
import {Attestation} from "./libs/Attestation";
import {AttestationRequest} from "./libs/AttestationRequest";
import {KeyPair} from "./libs/KeyPair";
import {AttestedObject} from "./libs/AttestedObject";
import {UseToken} from "./asn1/shemas/UseToken";
import {PrivateKeyInfo, SignedInfo, PublicKeyInfoValue} from "./asn1/shemas/AttestationFramework";
import {AsnParser} from "@peculiar/asn1-schema";
import {SignedAttestation} from "./libs/SignedAttestation";

const PREFIX_PATH = '../../../../build/test-results/';

describe("Utils tests", () => {
    test('uint8tohex test', () => {
        expect(uint8tohex(new Uint8Array([1,2]))).toBe("0102")
    })
});

describe("Attestation test", () => {

    const receiverPubPEM = readFileSync(PREFIX_PATH + 'receiver-pub.pem', 'utf8');

    const receiverPrivPEM = readFileSync(PREFIX_PATH + 'receiver-priv.pem', 'utf8');

    const attestationRequestPem = readFileSync(PREFIX_PATH + 'attestation-request.pem', 'utf8');
    const attestationRequestUint8 = base64ToUint8array(attestationRequestPem);

    const attRequest = AttestationRequest.fromBytes( attestationRequestUint8, KeyPair.publicFromBase64(receiverPubPEM) );


});

describe("Keys decode test", () => {

    const signedTokenDER = readFileSync(PREFIX_PATH + 'signed-devcon-ticket.der');

    const receiverPubPEM = readFileSync(PREFIX_PATH + 'receiver-pub.pem', 'utf8');
    const receiverPrivPEM = readFileSync(PREFIX_PATH + 'receiver-priv.pem', 'utf8');

    const receiverPubUint8 = base64ToUint8array(receiverPubPEM);
    const receiverPrivUint8 = base64ToUint8array(receiverPrivPEM);

    let privateKeyObj: PrivateKeyInfo = AsnParser.parse(uint8toBuffer( receiverPrivUint8), PrivateKeyInfo);
    let publicKeyObj: PublicKeyInfoValue = AsnParser.parse(uint8toBuffer( receiverPubUint8), PublicKeyInfoValue);

});

describe("SignedAttestation test", () => {


    const attestorPubPEM = readFileSync(PREFIX_PATH + 'attestor-pub.pem', 'utf8');
    const attestorPubUint8 = base64ToUint8array(attestorPubPEM);
    let publicKeyObj: PublicKeyInfoValue = AsnParser.parse(uint8toBuffer( attestorPubUint8), PublicKeyInfoValue);
    let attestorPubKey = KeyPair.publicFromUint(publicKeyObj.subjectPublicKey);

    const attestationPEM = readFileSync(PREFIX_PATH + 'attestation.pem', 'utf8');
    const attestationUint8 = base64ToUint8array(attestationPEM);

    let signedAttest = new SignedAttestation(attestationUint8, attestorPubKey)

});

describe("AttestedObject test", () => {

    // const attestedObject = AttestedObject.fromBytes( new Uint8Array(signedTokenDER), UseToken, KeyPair.privateFromKeyInfo(privateKeyObj) );

});

// test('should return true given internal link', () => {
//     expect(isInternalLink('/some-page')).toBe(true)
// })
