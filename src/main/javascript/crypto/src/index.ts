import { Asn1Der } from "./libs/DerUtility";
import { AttestationRequest } from "./libs/AttestationRequest";
import { AttestationCrypto } from "./libs/AttestationCrypto";
import {ATTESTATION_TYPE, keyPair} from "./libs/interfaces";
import { Cheque } from "./libs/Cheque";
import { ProofOfExponent } from "./libs/ProofOfExponent";
import {base64ToUint8array, hexStringToArray, uint8tohex} from "./libs/utils";
import {KeyPair} from "./libs/KeyPair";
import {IdentifierAttestation} from "./libs/IdentifierAttestation";
import {SignedDevconTicket} from "./asn1/SignedDevonTicket";
import {SignedAttestation} from "./libs/SignedAttestation";
import {Attestation} from "./libs/Attestation";
import {ChequeDecoder} from "./libs/ChequeDecoder";
import {SignedCheque} from "./asn1/shemas/SignedCheque";
import {AsnParser} from "@peculiar/asn1-schema";
import {SubjectPublicKeyInfo} from "./asn1/shemas/AttestationFramework";
import {AttestedObject} from "./libs/AttestedObject";
import {Authenticator, devconToken} from "./Authenticator";
const ASN1 = require('@lapo/asn1js');

export class main {
    crypto: AttestationCrypto;
    Asn1Der: Asn1Der;
    Asn1: any;
    constructor() {
        this.crypto = new AttestationCrypto();
        this.Asn1Der = new Asn1Der();
        this.Asn1 = ASN1;
    }
    createKeys() {
        return KeyPair.createKeys();
    }

    decodeTicket(magiclink: string){
        return new SignedDevconTicket(magiclink);
   }

    keysFromPrivateBase64(str: string){
        return KeyPair.privateFromAsn1base64(str);
    }

    createCheque(amount: number, receiverId: string, type: string, validityInMilliseconds: number, keys: KeyPair, secret: bigint) {
        return Cheque.createAndVerify(receiverId, type, amount, validityInMilliseconds, keys, secret);
    }

    requestAttest(receiverId: string, type: string, keys?: KeyPair) {
        if (!keys) keys = KeyPair.createKeys();
        let secret: bigint = this.crypto.makeSecret();
        let pok:ProofOfExponent = this.crypto.computeAttestationProof(secret);
        let request = AttestationRequest.fromData(receiverId, ATTESTATION_TYPE[type], pok, keys);
        return {
            request: request.getDerEncoding(),
            requestSignature: request.signature,
            requestSecret: Asn1Der.encode('SEQUENCE_30', Asn1Der.encode('OCTET_STRING', secret.toString(16)))
        }
    }

    // This part not needed in JS
    constructAttest( keys: KeyPair, issuerName: string, validityInMilliseconds: number, requestBytesDehHexStr: string): any {
        let attestRequest = AttestationRequest.fromBytes(Uint8Array.from(hexStringToArray(requestBytesDehHexStr)));
        let verify = 'Verify attestation signing request ' + ( attestRequest.verify() ? 'OK' : 'failed');
        return {
            verify,
        }
    }

    static getUseToken(
        // userKey: KeyPair,
        chequeSecret: bigint,
        attestationSecret: bigint,
        base64cheque: string,
        base64attestation: string,
        base64attestationPublicKey: string
    )
    {
        // let chequeSecret: bigint = BigInt('0x'+ uint8tohex(base64ToUint8array(base64chequeSecret)));
        // let attestationSecret: bigint = BigInt('0x'+ uint8tohex(base64ToUint8array(base64attestationSecret)));

        let cheque: Cheque = ChequeDecoder.fromBase64(base64cheque);
        if (!cheque.checkValidity()) {
            console.log("Could not validate cheque");
            throw new Error("Validation failed");
        }
        if (!cheque.verify()) {
            console.log("Could not verify cheque");
            throw new Error("Verification failed");
        }

        let keyUint8data = base64ToUint8array(base64attestationPublicKey);
        let key:SubjectPublicKeyInfo = AsnParser.parse(keyUint8data, SubjectPublicKeyInfo);

        // console.log('user key');
        // console.log(key.value.subjectPublicKey);

        let attestorKey = KeyPair.fromPublicHex(uint8tohex(new Uint8Array(key.value.subjectPublicKey)));

        let att = new SignedAttestation(base64attestation, attestorKey);

        if (!att.checkValidity()) {
            console.log("Could not validate attestation");
            throw new Error("Validation failed");
        }
        if (!att.verify()) {
            console.log("Could not verify attestation");
            throw new Error("Verification failed");
        }


        let redeem: AttestedObject = new AttestedObject(
            cheque, att,
            attestationSecret, chequeSecret);
        // console.log("redeem.getDerEncodeProof()");
        // console.log(redeem.getDerEncodeProof());

        let proof = redeem.getDerEncodeProof();

        let vec =
            uint8tohex(base64ToUint8array(base64cheque)) +
            uint8tohex(base64ToUint8array(base64attestation))+
            proof;
        return Asn1Der.encode('SEQUENCE_30', vec);

        // if (!redeem.checkValidity()) {
        //     console.log("Could not validate redeem request");
        //     throw new Error("Validation failed");
        // }
        // if (!redeem.verify()) {
        //     console.log("Could not verify redeem request");
        //     throw new Error("Verification failed");
        // }
// // TODO how should this actually be?
// SmartContract sc = new SmartContract();
// if (!sc.testEncoding(redeem.getPok())) {
//     System.err.println("Could not submit proof of knowledge to the chain");
//     throw new RuntimeException("Chain submission failed");
// }
 }

}
(window as any).Authenticator = Authenticator;

