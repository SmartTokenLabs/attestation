import {AttestedObject} from "./AttestedObject";
import {hexToBuf} from "bigint-conversion";
import {UseToken} from "../asn1/shemas/UseToken";
import {XMLconfigData} from "../data/tokenData";
import {KeyPair} from "./KeyPair";
import {Ticket} from "../Ticket";


export class Eip712Validator {
    private XMLConfig: any;
    constructor() {
        this.XMLConfig = XMLconfigData;
    }
    validateRequest(jsonInput: string) {
        try {
            let authenticationData = JSON.parse(jsonInput);

            let authenticationRootNode = JSON.parse(authenticationData.jsonSigned);

            // console.log(authenticationRootNode);

            let eip712Domain = authenticationRootNode.domain;
            let eip712Message = authenticationRootNode.message;

            // console.log(eip712Domain);
            // console.log(eip712Message);

            let attestedObject = this.retrieveAttestedObject(eip712Message);
            //
            // boolean accept = true;
            // accept &= validateDomain(eip712Domain);
            // accept &= validateAuthentication(auth);
            // accept &= verifySignature(authenticationData, attestedObject.getUserPublicKey());
            // accept &= validateAttestedObject(attestedObject);
            // return accept;
        } catch (e) {
            console.error('Validate error!');
            console.error(e);
            return false;
        }
    }

    retrieveAttestedObject(auth: any){
        let attestedObjectHex = auth.payload;

        let attestorKey = KeyPair.publicFromBase64(XMLconfigData.base64attestorPubKey);
        let issuerKey = KeyPair.publicFromBase64(XMLconfigData.base64senderPublicKey);

        let decodedAttestedObject = AttestedObject.fromBytes(new Uint8Array(hexToBuf(attestedObjectHex)), UseToken, attestorKey, Ticket, issuerKey);

        return decodedAttestedObject;
    }
}
