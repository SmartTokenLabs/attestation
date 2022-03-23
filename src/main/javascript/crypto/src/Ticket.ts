import {AttestationCrypto} from "./libs/AttestationCrypto";
import {KeyPair} from "./libs/KeyPair";
import {Asn1Der} from "./libs/DerUtility";
import {AttestableObject} from "./libs/AttestableObject";
import {base64ToUint8array, hexStringToArray, uint8toBuffer, uint8tohex} from "./libs/utils";
import {SignedDevconTicket} from "./asn1/shemas/SignedDevconTicket";
import {AsnParser} from "@peculiar/asn1-schema";
import {Attestable} from "./libs/Attestable";
/*
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

 */

export class Ticket extends AttestableObject implements Attestable {

    private ticketId: string;
    private ticketClass: number;
    private devconId: string;
    private magicLinkURLPrefix:string = "https://ticket.devcon.org/";

    private signature: string;
    private keys: {[index: string]:KeyPair};
    // protected encoded: string;


    constructor() {
        super();
    }

    fromData(devconId: string, ticketId: string, ticketClass:number, keys: {[index: string]:KeyPair} ) {
        this.ticketId = ticketId;
        this.ticketClass = ticketClass;
        this.devconId = devconId;
        this.keys = keys;
    }

    createWithCommitment(devconId: string, ticketId: string, ticketClass: number, commitment: Uint8Array, signature: string, keys: {[index: string]:KeyPair}) {
        this.fromData(devconId, ticketId, ticketClass, keys);
        this.commitment = commitment;
        this.signature = signature;
        this.encoded = this.encodeSignedTicket(this.makeTicket());

        if (!this.verify()) {
            throw new Error("Signature is invalid");
        }
    }

    static createWithMail(mail: string, devconId:string , ticketId: string, ticketClass: number, keys: {[index: string]:KeyPair}, secret: bigint): Ticket {
        let me = new this();
        me.fromData(devconId, ticketId, ticketClass, keys);
        let crypto = new AttestationCrypto();
        let signature;

        try {
            me.commitment = crypto.makeCommitment(mail, crypto.getType('mail'), secret);
            let asn1Tic = me.makeTicket();
            signature = keys[me.devconId].signRawBytesWithEthereum(hexStringToArray(asn1Tic));
        } catch (e) {
            throw new Error(e);
        }

        me.createWithCommitment(devconId, ticketId, ticketClass, me.commitment, signature, keys);
        return me;
    }

    private makeTicket() {
        let asnTicketIdType;
        try {
            let recoded = BigInt(this.ticketId).toString();
            if (this.ticketId == recoded) {
                asnTicketIdType = 'INTEGER';
            } else {
                asnTicketIdType = 'UTF8STRING';
            }
        } catch(e){
            asnTicketIdType = 'UTF8STRING';
        }
       
        let ticket: string =
            Asn1Der.encode('UTF8STRING', this.devconId)
            + Asn1Der.encode(asnTicketIdType, this.ticketId)
            + Asn1Der.encode('INTEGER', this.ticketClass)
            + Asn1Der.encode('OCTET_STRING', uint8tohex(this.commitment));
        return Asn1Der.encode('SEQUENCE_30', ticket);
    }

    encodeSignedTicket(ticket: string)  {
        let signedTicket:string =
            ticket
            + Asn1Der.encode('BIT_STRING', this.signature);
        return Asn1Der.encode('SEQUENCE_30', signedTicket);
    }

    public getDerEncodingWithPK(): string {
        let ticket = this.makeTicket();
        let signedTicket: string =
            ticket
            + Asn1Der.encode('OCTET_STRING', uint8tohex(this.commitment))
            + this.keys[this.devconId].getAsnDerPublic()
            + Asn1Der.encode('BIT_STRING', this.signature);
        return Asn1Der.encode('SEQUENCE_30', signedTicket);
    }

    public getDerEncoding():string {
        return this.encoded;
    }

    public verify(): boolean {
        return this.keys[this.devconId].verifyBytesWithEthereum(hexStringToArray(this.makeTicket()), this.signature);
    }

    public checkValidity(): boolean {
        // The ticket is always valid on its own. It depends on which conference it is used
        // and whether it has been revoked that decides if it can be used
        return true;
    }

    public getTicketId():string {
        return this.ticketId;
    }

    public getTicketClass(): number {
        return this.ticketClass;
    }

    public getSignature(): string {
        return this.signature;
    }

    static fromBase64(base64str: string, keys: {[index: string]:KeyPair}): Ticket {
        let me = new this();
        me.fromBytes(base64ToUint8array(base64str), keys);
        return me;
    }

    fromBytes(bytes: Uint8Array, keys: {[index: string]:KeyPair}) {
        const signedDevconTicket: SignedDevconTicket = AsnParser.parse(uint8toBuffer(bytes), SignedDevconTicket);

        let devconId:string = signedDevconTicket.ticket.devconId;
        let ticketId:string;
        if (signedDevconTicket.ticket.ticketId.tiketIdNumber) {
            ticketId = signedDevconTicket.ticket.ticketId.tiketIdNumber.toString();
        } else {
            ticketId = signedDevconTicket.ticket.ticketId.tiketIdString;
        }
        let ticketClassInt:number = signedDevconTicket.ticket.ticketClass;
        let commitment:Uint8Array = signedDevconTicket.ticket.commitment;

        let signature:Uint8Array = signedDevconTicket.signatureValue;
        
        this.createWithCommitment(devconId, ticketId, ticketClassInt, new Uint8Array(commitment), uint8tohex(new Uint8Array(signature)) , keys );
    }

    public getCommitment(): Uint8Array {
        return this.commitment;
    }


    public getUrlEncoding() {
        // TODO implement
        // SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(this.publicKey);
        // return URLUtility.encodeList(Arrays.asList(this.encoded, keyInfo.getPublicKeyData().getEncoded()));
    }

}
