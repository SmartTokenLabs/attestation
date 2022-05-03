import {AttestedObject} from "./AttestedObject";
import {UseToken} from "../asn1/shemas/UseToken";
import {XMLconfigData} from "../data/tokenData";
import {KeyPair} from "./KeyPair";
import {Ticket} from "../Ticket";
import {Eip712DomainInterface, SignatureUtility} from "./SignatureUtility";
import {hexStringToUint8, logger} from "./utils";
import {DEBUGLEVEL} from "../config";

export class Eip712Validator {
    private XMLConfig: any;
    protected domain: string;

    constructor() {
        this.XMLConfig = XMLconfigData;
    }

    static stringIsAValidUrl(domain: string): boolean {
        let parsedUrl;

        try {
            parsedUrl = new URL(domain);
        } catch (e) {
            logger(DEBUGLEVEL.LOW, 'cant construct url. Error:', e);
            return false;
        }

        return parsedUrl.protocol === "http:" || parsedUrl.protocol === "https:";
    };

    setDomainAndTimout(domain: string){
        if (!Eip712Validator.stringIsAValidUrl(domain)) throw new Error('wrong domain');
        this.domain = domain;
    }

    setDomain(domain: string){
        if (!Eip712Validator.stringIsAValidUrl(domain)) throw new Error('wrong domain');
        this.domain = domain;
    }

    getDomain(): string{
        return this.domain;
    }

    validateRequest(jsonInput: string) {
        try {
            let authenticationData = JSON.parse(jsonInput);

            let authenticationRootNode = JSON.parse(authenticationData.jsonSigned);

            let eip712Domain = authenticationRootNode.domain;
            let eip712Message = authenticationRootNode.message;

            let attestedObject = this.retrieveAttestedObject(eip712Message);

            // TODO implement
            return this.validateDomain(eip712Domain)
            // && this.validateAuthentication(auth);
            // accept &= verifySignature(authenticationData, attestedObject.getUserPublicKey());
            // accept &= validateAttestedObject(attestedObject);
            // return accept;
        } catch (e) {
            logger(DEBUGLEVEL.LOW, 'Validate error!', e);
            return false;
        }
    }

    // TODO
    // public boolean verifyTimeStamp(String timestamp) {

    validateDomain(domainToCheck: Eip712DomainInterface): boolean {
        if (domainToCheck.name.toLowerCase() !== this.domain.toLowerCase()) {
            logger(DEBUGLEVEL.LOW, "Domain name is not valid");
            return false;
        }

        if (domainToCheck.version !== SignatureUtility.Eip712Data['PROTOCOL_VERSION']) {
            logger(DEBUGLEVEL.LOW, "Protocol version is wrong");
            return false;
        }

        // we dont use that fields at the moment. maybe have to uncomment and fix in the future
        // if (domainToCheck.chainId !== encoder.getChainId())) {
        //     console.error("Chain ID is wrong");
        //     return false;
        // }
        // if (domainToCheck.verifyingContract !== encoder.getVerifyingContract()) {
        //     console.error("Verifying contract is wrong");
        //     return false;
        // }
        // if (domainToCheck.salt !== encoder.getSalt()) {
        //     console.error("Salt is wrong");
        //     return false;
        // }
        return true;

    }

    retrieveAttestedObject(auth: any){
        let attestedObjectHex = auth.payload;

        let attestorKey = KeyPair.publicFromBase64(XMLconfigData.base64attestorPubKey);
        let issuerKeys = XMLconfigData.base64senderPublicKeys;

        let decodedAttestedObject = AttestedObject.fromBytes(hexStringToUint8(attestedObjectHex), UseToken, attestorKey, Ticket, issuerKeys);
        return decodedAttestedObject;
    }

    public verifySignature(signedJsonInput: string, pkAddress: string): boolean {

        let tokenData = JSON.parse(signedJsonInput);
        let signatureInHex = tokenData.signatureInHex;
        let jsonSigned = JSON.parse(tokenData.jsonSigned);

        let publicKey = SignatureUtility.recoverPublicKeyFromTypedMessageSignature(jsonSigned, signatureInHex);
        let userKey = KeyPair.fromPublicHex(publicKey.substr(2));

        if (pkAddress.toLowerCase() !== jsonSigned.message.address.toLowerCase()){
            logger(DEBUGLEVEL.LOW, 'message.address is not equal pkAddress');
            return false;
        }
        if (pkAddress.toLowerCase() !== userKey.getAddress().toLowerCase()){
            logger(DEBUGLEVEL.LOW, 'Recovered address is not equal pkAddress');
            return false;
        }
        return true;

    }

    // TODO check all methods
    // Eip712Validator.java
}
