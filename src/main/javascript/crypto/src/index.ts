import { Asn1Der } from "./libs/DerUtility";
import { AttestationRequest } from "./libs/AttestationRequest";
import { AttestationCrypto } from "./libs/AttestationCrypto";
import {ATTESTATION_TYPE, keyPair} from "./libs/interfaces";
import { Cheque } from "./libs/Cheque";
import { ProofOfExponent } from "./libs/ProofOfExponent";
import {hexStringToArray} from "./libs/utils";
import {KeyPair} from "./libs/KeyPair";
import {IdentifierAttestation} from "./libs/IdentifierAttestation";
import {SignedDevconTicket} from "./asn1/SignedDevonTicket";
import {SignedAttestation} from "./libs/SignedAttestation";
import {Attestation} from "./libs/Attestation";
import {ChequeDecoder} from "./libs/ChequeDecoder";
const ASN1 = require('@lapo/asn1js');

class main {
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

    decodeCheque(str: string){
        new ChequeDecoder(str);
    }

    decodeAttestation(str: string){
        new SignedAttestation(str);
    }

    // This part not needed in JS
    constructAttest( keys: KeyPair, issuerName: string, validityInMilliseconds: number, requestBytesDehHexStr: string): any {
        let attestRequest = AttestationRequest.fromBytes(Uint8Array.from(hexStringToArray(requestBytesDehHexStr)));
        let verify = 'Verify attestation signing request ' + ( attestRequest.verify() ? 'OK' : 'failed');
        return {
            verify,
        }
    }

    receiveCheque(userKey: KeyPair, chequeSecret: bigint,
    attestationSecret: bigint, base64cheque: string, base64attestation: string, attestationKey: string){

    // let cheque: Cheque = new ChequeDecoder(base64cheque);
    // let cheque: Cheque = new ChequeDecoder(base64cheque);
//     byte[] attestationBytes = DERUtility.restoreBytes(Files.readAllLines(pathAttestation));
//     AsymmetricKeyParameter attestationProviderKey = PublicKeyFactory.createKey(
//         DERUtility.restoreBytes(Files.readAllLines(pathAttestationKey)));
//     SignedAttestation att = new SignedAttestation(attestationBytes, attestationProviderKey);
//
//     if (!cheque.checkValidity()) {
//     System.err.println("Could not validate cheque");
//     throw new RuntimeException("Validation failed");
// }
// if (!cheque.verify()) {
//     System.err.println("Could not verify cheque");
//     throw new RuntimeException("Verification failed");
// }
// if (!att.checkValidity()) {
//     System.err.println("Could not validate attestation");
//     throw new RuntimeException("Validation failed");
// }
// if (!att.verify()) {
//     System.err.println("Could not verify attestation");
//     throw new RuntimeException("Verification failed");
// }
//
// AttestedObject redeem = new AttestedObject(cheque, att, userKeys, attestationSecret, chequeSecret, crypto);
// if (!redeem.checkValidity()) {
//     System.err.println("Could not validate redeem request");
//     throw new RuntimeException("Validation failed");
// }
// if (!redeem.verify()) {
//     System.err.println("Could not verify redeem request");
//     throw new RuntimeException("Verification failed");
// }
// // TODO how should this actually be?
// SmartContract sc = new SmartContract();
// if (!sc.testEncoding(redeem.getPok())) {
//     System.err.println("Could not submit proof of knowledge to the chain");
//     throw new RuntimeException("Chain submission failed");
// }
 }

}
(window as any).CryptoTicket = main;
(window as any).SignedDevconTicket = SignedDevconTicket;
(window as any).signed = SignedAttestation;

