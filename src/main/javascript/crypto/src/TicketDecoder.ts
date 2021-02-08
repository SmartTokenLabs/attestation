import {base64ToUint8array, uint8tohex} from "./libs/utils";
import {AsnParser} from "@peculiar/asn1-schema";
import {PublicKeyInfo, SignedDevconTicket} from "./asn1/shemas/SignedDevconTicket";
import {Ticket} from "./Ticket";
import {KeyPair} from "./libs/KeyPair";

export class TicketDecoder {
    constructor() {
    }

    static fromBase64(base64str: string, keys: KeyPair): Ticket {
        let uint8data = base64ToUint8array(base64str);
        const signedDevconTicket: SignedDevconTicket = AsnParser.parse(uint8data, SignedDevconTicket);

        let devconId:number = signedDevconTicket.ticket.devconId;
        let ticketId:number = signedDevconTicket.ticket.ticketId;
        let ticketClassInt:number = signedDevconTicket.ticket.ticketClass;

        let commitment:Uint8Array = signedDevconTicket.commitment;
        let signature:Uint8Array = signedDevconTicket.signatureValue;
        return Ticket.createWithRiddle(devconId, ticketId, ticketClassInt, new Uint8Array(commitment), uint8tohex(new Uint8Array(signature)) , keys );
    }
}
