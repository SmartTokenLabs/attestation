import {AttestationCrypto} from "./libs/AttestationCrypto";
import {KeyPair} from "./libs/KeyPair";
import {ATTESTATION_TYPE} from "./libs/interfaces";
import {Asn1Der} from "./libs/DerUtility";
import {SignatureUtility} from "./libs/SignatureUtility";
import {AttestableObject} from "./libs/AttestableObject";
import {base64ToUint8array, uint8toBuffer, uint8tohex} from "./libs/utils";
import {SignedDevconTicket} from "./asn1/shemas/SignedDevconTicket";
import {AsnParser} from "@peculiar/asn1-schema";

class TicketClass {
    list: {[index:string]: number} = {
        REGULAR: 0,
        VIP: 1,
        SPEAKER: 2,
        STAFF: 3,
    }

    static decodeList: {[index:number]: string} = {
        0: "REGULAR",
        1: "VIP",
        2: "SPEAKER",
        3: "STAFF"
    }

    constructor(private value: string) {
    }

    static fromInt(value: number): TicketClass {
        return new this(TicketClass.decodeList[value]);
    }

    public getValue() { return this.list[this.value]; }
}

export class Ticket extends AttestableObject {

    private mail: string;
    private secret: bigint;
    private signature: string;

    private ticketId: number;
    private ticketClass: TicketClass;
    private devconId: number;
    private keys: KeyPair;

    constructor() {
        super();
    }

    fromData(ticketId: number, ticketClass: TicketClass, devconId: number, keys: KeyPair){
        this.ticketId = ticketId;
        this.ticketClass = ticketClass;
        this.devconId = devconId;
        this.keys = keys;
    }

    createWithRiddle(devconId: number, ticketId: number, ticketClass: number, commitment: Uint8Array, signature: string, keys: KeyPair) {
        this.fromData(ticketId, TicketClass.fromInt(ticketClass), devconId, keys);

        this.commitment = commitment;
        this.signature = signature;
        this.encoded = this.encodeSignedTicket(this.makeTicket());
        if (!this.verify()) {
            throw new Error("Signature is invalid");
        }
    }

    static createWithMail(mail: string, devconId:number , ticketId: number, ticketClass: TicketClass, conferenceId: number, keys: KeyPair, secret: bigint): Ticket {
        let me = new this();
        me.fromData(ticketId, ticketClass, conferenceId, keys);

        me.devconId = devconId;
        me.mail = mail;
        me.secret = secret;
        let crypto = new AttestationCrypto();
        me.commitment = crypto.makeCommitment(mail, ATTESTATION_TYPE['mail'], secret);
        let asn1Tic = me.makeTicket();

        me.signature = SignatureUtility.sign(asn1Tic, keys);
        me.encoded = me.encodeSignedTicket(asn1Tic);
        if (!me.verify()) {
            throw new Error("Public and private keys are incorrect");
        }

        return me;
    }

    private makeTicket() {
        let ticket: string =
            Asn1Der.encode('INTEGER', this.devconId)
            + Asn1Der.encode('INTEGER', this.ticketId)
            + Asn1Der.encode('INTEGER', this.ticketClass.getValue());
        return Asn1Der.encode('SEQUENCE_30', ticket);
    }

    encodeSignedTicket(ticket: string)  {
        let signedTicket:string =
            ticket
            + Asn1Der.encode('OCTET_STRING', this.commitment)
            + Asn1Der.encode('BIT_STRING', this.signature);
        return Asn1Der.encode('SEQUENCE_30', signedTicket);
    }

    public getDerEncodingWithPK(): string {
        let ticket = this.makeTicket();
        let signedTicket: string =
            ticket
            + Asn1Der.encode('OCTET_STRING', this.commitment)
            + this.keys.getAsnDerPublic()
            + Asn1Der.encode('BIT_STRING', this.signature);
        return Asn1Der.encode('SEQUENCE_30', signedTicket);
    }

    public verify(): boolean {
        return SignatureUtility.verify(this.makeTicket(), this.signature, this.keys);
    }

    public checkValidity(): boolean {
        // The ticket is always valid on its own. It depends on which conference it is used
        // and whether it has been revoked that decides if it can be used
        return true;
    }

    public getTicketId():number {
        return this.ticketId;
    }

    public getTicketClass(): TicketClass {
        return this.ticketClass;
    }

    public getSignature(): string {
        return this.signature;
    }

    static fromBase64(base64str: string, keys: KeyPair): Ticket {
        let me = new this();
        me.fromBytes(base64ToUint8array(base64str), keys);
        return me;
    }

    fromBytes(bytes: Uint8Array, keys: KeyPair) {
        const signedDevconTicket: SignedDevconTicket = AsnParser.parse(uint8toBuffer(bytes), SignedDevconTicket);

        let devconId:number = signedDevconTicket.ticket.devconId;
        let ticketId:number = signedDevconTicket.ticket.ticketId;
        let ticketClassInt:number = signedDevconTicket.ticket.ticketClass;

        let commitment:Uint8Array = signedDevconTicket.commitment;
        let signature:Uint8Array = signedDevconTicket.signatureValue;
        this.createWithRiddle(devconId, ticketId, ticketClassInt, new Uint8Array(commitment), uint8tohex(new Uint8Array(signature)) , keys );
    }

}
