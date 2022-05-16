import { AttestationCrypto } from "./libs/AttestationCrypto";
import { KeyPair, keysArray } from "./libs/KeyPair";
import { Asn1Der } from "./libs/DerUtility";
import { AttestableObject } from "./libs/AttestableObject";
import { base64ToUint8array, hexStringToArray, uint8tohex } from "./libs/utils";
import { SignedDevconTicket } from "./asn1/shemas/SignedDevconTicket";
import { AsnParser } from "@peculiar/asn1-schema";
import { Attestable } from "./libs/Attestable";

export class Ticket extends AttestableObject implements Attestable {

    private ticketId: string;
    private ticketClass: number;
    private devconId: string;
    private magicLinkURLPrefix:string = "https://ticket.devcon.org/";

    private signature: string;
    private keys: keysArray;
    private key: KeyPair;

    private isLegasy = false;

    // protected encoded: string;


    constructor() {
        super();
    }

    fromData(devconId: string, ticketId: string, ticketClass:number, keys: keysArray ) {
        this.ticketId = ticketId;
        this.ticketClass = ticketClass;
        this.devconId = devconId;
        this.keys = keys;

        this.key = keys[devconId];
    }

    createWithCommitment(devconId: string, ticketId: string, ticketClass: number, commitment: Uint8Array, signature: string, keys: keysArray) {
        this.fromData(devconId, ticketId, ticketClass, keys);
        this.commitment = commitment;
        this.signature = signature;
        this.encoded = this.encodeSignedTicket(this.makeTicket());

        if (!this.verify()) {
            throw new Error("Signature is invalid");
        }
    }

    static createWithMail(mail: string, devconId:string , ticketId: string, ticketClass: number, keys: keysArray, secret: bigint): Ticket {
        let me = new this();
        me.fromData(devconId, ticketId, ticketClass, keys);

        let crypto = new AttestationCrypto();
        let signature;

        try {
            me.commitment = crypto.makeCommitment(mail, crypto.getType('mail'), secret);
            let asn1Tic = me.makeTicket();
            // signature = KeyPair.publicFromSubjectPublicKeyInfo( keys[me.devconId] ).signRawBytesWithEthereum(hexStringToArray(asn1Tic));
            signature = me.key.signRawBytesWithEthereum(hexStringToArray(asn1Tic));
        } catch (e) {
            throw new Error(e);
        }

        me.createWithCommitment(devconId, ticketId, ticketClass, me.commitment, signature, keys);
        return me;
    }

    private makeTicket() {
        let ticketId:string;
        try {
            const asBN = BigInt(this.ticketId);
            ticketId = Asn1Der.encode('INTEGER', asBN);
        } catch(e){
            ticketId = Asn1Der.encode('UTF8STRING', this.ticketId);
            // console.log("ticketID is string: ", this.ticketId);
        }

        let ticket: string =
            Asn1Der.encode('UTF8STRING', this.devconId)
            + ticketId
            + Asn1Der.encode('INTEGER', this.ticketClass);

            if (!this.isLegasy) {
                ticket += Asn1Der.encode('OCTET_STRING', uint8tohex(this.commitment));
            }
        return Asn1Der.encode('SEQUENCE_30', ticket);
    }

    encodeSignedTicket(ticket: string)  {
        if (this.isLegasy) {
            ticket += Asn1Der.encode('OCTET_STRING', uint8tohex(this.commitment));
        }
        ticket += Asn1Der.encode('BIT_STRING', this.signature);
        return Asn1Der.encode('SEQUENCE_30', ticket);
    }

    public getDerEncodingWithPK(): string {
        let ticket = this.makeTicket();
        let signedTicket: string =
            ticket
            + Asn1Der.encode('OCTET_STRING', uint8tohex(this.commitment))
            + this.key.getAsnDerPublic()
            + Asn1Der.encode('BIT_STRING', this.signature);
        return Asn1Der.encode('SEQUENCE_30', signedTicket);
    }

    public getDerEncoding():string {
        return this.encoded;
    }

    public verify(): boolean {
        return this.key.verifyBytesWithEthereum(hexStringToArray(this.makeTicket()), this.signature);
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

    static fromBase64(base64str: string, keys: keysArray): Ticket {
        let me = new this();
        me.fromBytes(base64ToUint8array(base64str), keys);
        return me;
    }

    fromBytes(bytes: Uint8Array, keys: keysArray) {
        const signedDevconTicket: SignedDevconTicket = AsnParser.parse(bytes, SignedDevconTicket);

        let devconId:string = signedDevconTicket.ticket.devconId;

        this.key = keys[devconId];

        let idAsNumber = signedDevconTicket.ticket.tiketIdNumber;
        let ticketId:string = idAsNumber ? idAsNumber.toString() : signedDevconTicket.ticket.tiketIdString;
        let ticketClassInt:number = signedDevconTicket.ticket.ticketClass;

        let commitment:Uint8Array;
        if (signedDevconTicket.ticket.commitment) {
            commitment = signedDevconTicket.ticket.commitment;
        } else {
            commitment = signedDevconTicket.commitment;
            this.isLegasy = true;
        }
         
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
