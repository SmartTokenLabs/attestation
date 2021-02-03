import { Asn1Der } from "./libs/DerUtility";
import { AttestationCrypto } from "./libs/AttestationCrypto";
import {base64ToUint8array, uint8tohex} from "./libs/utils";
import {KeyPair} from "./libs/KeyPair";
import {SignedAttestation} from "./libs/SignedAttestation";
import {AsnParser} from "@peculiar/asn1-schema";
import {SubjectPublicKeyInfo} from "./asn1/shemas/AttestationFramework";
import {Authenticator, devconToken} from "./Authenticator";
import {Ticket} from "./Ticket";
import {TicketDecoder} from "./TicketDecoder";
import {AttestedObject} from "./libs/AttestedObject";
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

    static getUseTicket(
        // userKey: KeyPair,
        ticketSecret: bigint,
        attestationSecret: bigint,
        base64ticket: string,
        base64attestation: string,
        base64attestationPublicKey: string,
        base64senderPublicKey: string
    )
    {
        let ticket: Ticket = TicketDecoder.fromBase64(base64ticket, KeyPair.fromPublicHex(base64senderPublicKey));
        if (!ticket.checkValidity()) {
            console.log("Could not validate cheque");
            throw new Error("Validation failed");
        }
        if (!ticket.verify()) {
            console.log("Could not verify ticket");
            throw new Error("Verification failed");
        }
        console.log('ticked valid (signature OK)');

        let keyUint8data = base64ToUint8array(base64attestationPublicKey);
        let key:SubjectPublicKeyInfo = AsnParser.parse(keyUint8data, SubjectPublicKeyInfo);

        let attestorKey = KeyPair.fromPublicHex(uint8tohex(new Uint8Array(key.value.subjectPublicKey)));

        console.log('lets test attestaion:');
        let att = new SignedAttestation(base64attestation, attestorKey);

        if (!att.checkValidity()) {
            console.log("Could not validate attestation");
            throw new Error("Validation failed");
        }
        if (!att.verify()) {
            console.log("Could not verify attestation");
            throw new Error("Verification failed");
        }
        console.log('attestaion valid');

        let redeem: AttestedObject = new AttestedObject(
            ticket, att,
            BigInt(attestationSecret), BigInt(ticketSecret));
        console.log("redeem.getDerEncodeProof(): ");
        console.log(redeem.getDerEncodeProof());

        return redeem.getDerEncodeProof();

 }

}
(window as any).Authenticator = Authenticator;

