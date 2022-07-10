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
    protected verifyingContract: string;
    protected chainId: number;
    protected salt: string;
    protected primaryName: string;

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

    setSalt(salt: string){
        this.salt = salt;
    }

    getSalt(): string{
        return this.salt;
    }

    //getPrimaryName

    setPrimaryName(primaryName: string){
        this.primaryName = primaryName;
    }

    getPrimaryName(): string{
        return this.primaryName;
    }


    setChainId(chainId: number){
        if (chainId < 1) throw new Error('ChainId should be a positive number');
        this.chainId = chainId;
    }

    getChainId(): number{
        return this.chainId;
    }

    validateDomain(domainToCheck: Eip712DomainInterface): boolean {
        if ( !domainToCheck ) {
            logger(DEBUGLEVEL.LOW, "Input param domainToCheck required");
            return false;
        }

        if (!domainToCheck.name || (domainToCheck.name.toLowerCase() !== this.domain.toLowerCase())) {
            logger(DEBUGLEVEL.LOW, "Domain name is not valid");
            return false;
        }

        if (!domainToCheck.version || (domainToCheck.version !== SignatureUtility.Eip712Data['PROTOCOL_VERSION'])) {
            logger(DEBUGLEVEL.LOW, "Protocol version is wrong");
            return false;
        }

        if (this.chainId && (domainToCheck.chainId !== this.chainId)) {
            logger(DEBUGLEVEL.LOW, "Chain ID is wrong");
            return false;
        }

        if (this.verifyingContract && (domainToCheck.verifyingContract !== this.verifyingContract)) {
            logger(DEBUGLEVEL.LOW, "Verifying contract is wrong");
            return false;
        }

        if (this.salt && (domainToCheck.salt !== this.salt)) {
            logger(DEBUGLEVEL.LOW, "Salt is wrong");
            return false;
        }

        return true;

    }

    retrieveAttestedObject(auth: any){
        let attestedObjectHex = auth.payload;

        let attestorKey = KeyPair.publicFromBase64orPEM(XMLconfigData.base64attestorPubKey);
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
