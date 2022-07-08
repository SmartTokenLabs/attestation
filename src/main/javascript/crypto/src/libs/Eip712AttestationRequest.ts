import {Validateable} from "./Validateable";
import {Verifiable} from "./Verifiable";
import {JsonEncodable} from "../intefaces/JsonEncodable";
import {AttestationRequest} from "./AttestationRequest";
import {KeyPair} from "./KeyPair";
import {FullProofOfExponent} from "./FullProofOfExponent";
import {SignatureUtility} from "./SignatureUtility";
import {base64ToUint8array, hexStringToBase64Url, logger} from "./utils";
import {Nonce} from "./Nonce";
import {Eip712Token} from "./Eip712Token";
import {Timestamp} from "./Timestamp";
import {DEBUGLEVEL} from "../config";

export class Eip712AttestationRequest extends Eip712Token implements JsonEncodable, Verifiable, Validateable {
    private jsonEncoding: string;
    private usageValue: string;
    private attestationRequest: AttestationRequest;
    private acceptableTimeLimit: number;
    private userKey: KeyPair;
    // private publicKey: KeyPair;

    //static DEFAULT_TIME_LIMIT_MS:number = 1000*60*20; // 20 minutes

    private Eip712UserDataTypes: {name: string, type: string}[]  = [
        // {name: 'address', type: 'string'},
        {name: 'payload', type: 'string'},
        {name: 'description', type: 'string'},
        {name: 'timestamp', type: 'string'},
        {name: 'identifier', type: 'string'},
    ]
    private Eip712UserDataPrimaryName: string = "AttestationRequest";
    private Eip712UserDataDescription: string = "Linking Ethereum address to phone or email";

    constructor(userKey: KeyPair = null, acceptableTimeLimit: number = Timestamp.DEFAULT_TIME_LIMIT_MS) {
        super();
        this.userKey = userKey;
        this.acceptableTimeLimit = acceptableTimeLimit;
        this.usageValue = this.Eip712UserDataDescription;
    }

    setUsageValue(usageValue: string){
        this.usageValue = usageValue;
    }

    async addData(attestorDomain: string, acceptableTimeLimit: number = Timestamp.DEFAULT_TIME_LIMIT_MS, identifier: string, request: AttestationRequest) {
        this.setDomain(attestorDomain);

        // this.attestationRequest = AttestationRequest.fromData(type,pok);
        this.attestationRequest = request;
        this.acceptableTimeLimit = acceptableTimeLimit;

        this.jsonEncoding = await this.makeToken(identifier);

        try {
            // decode JSON and fill publicKey
            this.fillJsonData(this.jsonEncoding);
        } catch (e){
            logger(DEBUGLEVEL.LOW, e);
            return false;
        }
    }

    fillJsonData(json: string){
        if (!json) throw new Error('Empty json');

        this.jsonEncoding = json;
        let tokenData = JSON.parse(json);
        let signatureInHex = tokenData.signatureInHex;
  
        let jsonSigned = JSON.parse(tokenData.jsonSigned);
        this.eip712DomainData = jsonSigned.domain;
        this.data = jsonSigned.message;

        try {
            let publicKey = SignatureUtility.recoverPublicKeyFromTypedMessageSignature(jsonSigned, signatureInHex);
            this.requestorKeys = KeyPair.fromPublicHex(publicKey.substr(2));
            logger(DEBUGLEVEL.HIGH, 'restored address: ' + this.requestorKeys.getAddress());
        } catch (e){
            let m = "Recover Address failed with error:" + e;
            logger(DEBUGLEVEL.LOW, m, e);
            throw new Error(m);
        }

        if (!this.attestationRequest){
            this.attestationRequest = AttestationRequest.fromBytes(base64ToUint8array( this.data.payload));
        }

        this.constructorCheck();
    }

    constructorCheck() {
        if (!this.verify()) {
            throw new Error("Could not verify Eip712 AttestationRequest");
        }
        logger(DEBUGLEVEL.HIGH, 'Eip712 Attestaion Request verify OK');
    }

    async makeToken(identifier: string) {
        let userAddress: string;
        if (this.userKey) {
            userAddress = this.userKey.getAddress();
        } else {
            userAddress = await SignatureUtility.connectMetamaskAndGetAddress();
        }


        let nonceTimestamp = Nonce.getTimestamp(this.attestationRequest.getPok().getNonce());
        let ts = new Timestamp(nonceTimestamp).getTimeAsString();

        let userData = {
            payload: hexStringToBase64Url(this.attestationRequest.getDerEncoding()),
            description: this.usageValue,
            timestamp: ts,
            identifier: identifier,
            // address: userAddress,
        };

        return await SignatureUtility.signEIP712WithBrowserWallet(this.domain, userData, this.Eip712UserDataTypes, this.Eip712UserDataPrimaryName, this.userKey);

    }

    setAcceptableTimeLimit(limit: number){
        this.acceptableTimeLimit = limit;
    }

    public getJsonEncoding():string {
        return this.jsonEncoding;
    }

    public verify(): boolean {

        if (!this.attestationRequest.verify()) {
            logger(DEBUGLEVEL.MEDIUM, "Could not verify proof");
            return false;
        }

        return true;

    }

    public checkValidity(): boolean {

        if (!this.validateDomain(this.eip712DomainData)){
            logger(DEBUGLEVEL.MEDIUM, "Domain invalid");
            return false;
        }

        if (this.data.description !== this.usageValue) {
            logger(DEBUGLEVEL.MEDIUM,'Description is not correct. :' + this.data.description + ' !== ' + this.usageValue);
            return false;
        };

        let timestamp: Timestamp = new Timestamp(this.data.timestamp);
        timestamp.setValidity(this.acceptableTimeLimit);
        if (!timestamp.validateTimestamp()) {

            logger(DEBUGLEVEL.LOW, `timestamp is not correct. timestamp = ${this.data.timestamp}, acceptableTimeLimit = ${this.acceptableTimeLimit}`);
            return false;
        }

        if (!new Nonce().validateNonce(
            this.getPok().getNonce(),
            this.requestorKeys.getAddress(),
            this.domain,
            Timestamp.stringTimestampToLong(this.data.timestamp)-this.acceptableTimeLimit,
            Timestamp.stringTimestampToLong(this.data.timestamp)+this.acceptableTimeLimit)) {
            logger(DEBUGLEVEL.LOW, 'nonce is not correct');
            return false;
        }
        return true;
    }


    public getIdentifier(): string {
        return this.data.identifier;
    }

    public getType(): number {
        return this.attestationRequest.getType();
    }

    public getPok(): FullProofOfExponent {
        return this.attestationRequest.getPok();
    }

    public getUserPublicKey(): KeyPair {
        return this.requestorKeys;
    }

}
