import { KeyPair } from "./KeyPair";
import {AttestationCrypto} from "./AttestationCrypto";
import {Ticket} from "../Ticket";
import {PublicIdentifierProof} from "./PublicIdentifierProof";
import {base64ToUint8array, hexStringToBase64Url} from "./utils";
import {ATTESTATION_TYPE} from "./interfaces";
import {FullProofOfExponent} from "./FullProofOfExponent";

export class Issuer {
    static constructTicket(mail: string, devconID: string, ticketID: string, ticketClass: number, issuerKeyPair: KeyPair):string {
        let sharedSecret:bigint = new AttestationCrypto().makeSecret();
        let ticket:Ticket = Ticket.createWithMail(mail, devconID, ticketID, ticketClass, {'namedEcPubKey':issuerKeyPair}, sharedSecret);
        if (!ticket.checkValidity()) {
            throw new Error("Something went wrong and the constructed ticket could not be validated");
        }

        if (!ticket.verify()) {
            throw new Error("Something went wrong and the constructed ticket could not be verified");
        }

        let pok:PublicIdentifierProof = PublicIdentifierProof.fromSecret(ticket.getCommitment(),
                mail, ATTESTATION_TYPE['mail'], sharedSecret);
        if (!pok.verify()) {
            throw new Error("Something went wrong and the commitment in the ticket could not be verified according to the email.");
        }

        let ticketInUrl:string = hexStringToBase64Url(ticket.getDerEncoding());
        let pokInUrl:string = hexStringToBase64Url(pok.getInternalPok().getDerEncoding());

        return `?ticket=${ticketInUrl}&pok=${pokInUrl}&secret=${sharedSecret.toString()}&mail=${encodeURIComponent(mail)}`
    }

    static validateTicket(base64urlTicket:string, base64urlPok: string, mail: string, issuerPubKey:KeyPair) {
        let ticket = new Ticket();

        ticket.fromBytes(base64ToUint8array(base64urlTicket),  {'6':issuerPubKey});
        if (!ticket.checkValidity()) {
            throw new Error("Something went wrong and the constructed ticket could not be validated");
        }

        if (!ticket.verify()) {
            throw new Error("Something went wrong and the constructed ticket could not be verified");
        }

        let internalPok:FullProofOfExponent = FullProofOfExponent.fromBytes(base64ToUint8array(base64urlPok));
        let pok:PublicIdentifierProof = PublicIdentifierProof.fromPOK(ticket.getCommitment(), mail, ATTESTATION_TYPE['mail'], internalPok);

        if (!pok.verify()) {
            throw new Error("Something went wrong and the commitment in the ticket could not be verified according to the email");
        }

        return true;
    }
}