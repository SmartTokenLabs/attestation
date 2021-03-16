import {Eip712Validator} from "./Eip712Validator";
import {Validateable} from "./Validateable";
import {Verifiable} from "./Verifiable";
import {JsonEncodable} from "../intefaces/JsonEncodable";
import {AttestationRequest} from "./AttestationRequest";
import {KeyPair} from "./KeyPair";
import {FullProofOfExponent} from "./FullProofOfExponent";
import {SignatureUtility} from "./SignatureUtility";
import {
    base64toBase64Url,
    base64ToUint8array,
    hexStringToArray, hexStringToBase64Url, hexStringToUint8,
    pemOrBase64Orbase64urlToString,
    uint8arrayToBase64,
    uint8tohex
} from "./utils";
import {Nonce} from "./Nonce";

export class Eip712AttestationRequest extends Eip712Validator implements JsonEncodable, Verifiable, Validateable {
    private jsonEncoding: string;
    private attestationRequest: AttestationRequest;
    // TODO change to 100000
    private acceptableTimeLimit: number = 10000000;
    // TODO type it
    private data: any;
    private eip712DomainData: any;
    private requestorKeys: KeyPair;

    static Eip712UserData: {[index: string]:string|number}  = {
        address: '',
        description: '',
        identifier: '',
        payload: '',
        timestamp: 0
    }
    static Eip712UserDataTypes: {name: string, type: string}[]  = [
        {name: 'address', type: 'string'},
        {name: 'description', type: 'string'},
        {name: 'identifier', type: 'string'},
        {name: 'payload', type: 'string'},
        // {name: 'timestamp', type: 'uint256'},
        {name: 'timestamp', type: 'string'},
    ]
    static Eip712UserDataPrimaryName: string = "AttestationRequest";
    static Eip712UserDataDescription: string = "Linking Ethereum address to phone or email";

    async addData(attestorDomain: string, identifier: string, request: AttestationRequest) {
        this.setDomainAndTimout(attestorDomain);

        // this.attestationRequest = AttestationRequest.fromData(type,pok);
        this.attestationRequest = request;

        this.jsonEncoding = await this.makeToken(identifier);

        // console.log('lets fillJsonData');
        // console.log(this.jsonEncoding);
        try {
            // decode JSON and fill publicKey
            this.fillJsonData(this.jsonEncoding);
        } catch (e){
            console.log(e);
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
            console.log('restored address: ' + this.requestorKeys.getAddress());
        } catch (e){
            let m = "Recover Address failed with error:" + e;
            console.log(m)
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
        console.log('verify OK');
    }

    async makeToken(identifier: string) {

        let userAddress = await SignatureUtility.connectMetamaskAndGetAddress();

        let ts = Date().toString();
        ts = ts.substr(0, ts.indexOf('(') - 1);

        let userData = {
            payload: hexStringToBase64Url(this.attestationRequest.getDerEncoding()),
            description: Eip712AttestationRequest.Eip712UserDataDescription,
            timestamp: ts,
            identifier: identifier,
            address: userAddress,
        };


        return await SignatureUtility.signEIP712WithBrowserWallet(this.domain, userData, Eip712AttestationRequest.Eip712UserDataTypes, Eip712AttestationRequest.Eip712UserDataPrimaryName );
    }

    setAcceptableTimeLimit(limit: number){
        this.acceptableTimeLimit = limit;
    }

    public getJsonEncoding():string {
        return this.jsonEncoding;
    }

    public verify(): boolean {
        if (!this.attestationRequest.verify()) {
            return false;
        }

        if (!this.verifySignature(this.jsonEncoding, this.data.address)) {
            return false;
        }

        return this.verifyDomainData();

    }

    public verifyDomainData(): boolean{
        return (this.eip712DomainData.name.toLowerCase() === this.getDomain().toLowerCase())
            && (this.eip712DomainData.version === SignatureUtility.Eip712Data['PROTOCOL_VERSION']);
    }

    public checkValidity(): boolean {

        if (this.data.description !== Eip712AttestationRequest.Eip712UserDataDescription) {
            console.log('Description is not correct');
            return false;
        };

        if (!this.verifyTimeStamp(Date.parse(this.data.timestamp))) {
            console.log('Timelimit expired');
            return false;
        };

        if (this.requestorKeys.getAddress().toLowerCase() !== this.data.address.toLowerCase()) {
            console.log('Keys doesnt fit');
            return false;
        };

        if (! (new Nonce().validateNonce(this.getPok().getNonce(), this.getIdentifier(), this.data.address, this.domain))) {
            console.log('Nonce check failed');
            return false;
        };
        return true;
    }

    private verifyTimeStamp( timestamp: number): boolean {
        let currentTime = Date.now();
        // Verify timestamp is still valid and not too old
        if ((timestamp < currentTime + this.acceptableTimeLimit) &&
    (timestamp > currentTime - this.acceptableTimeLimit)) {
            return true;
        }
        return false;
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

    public getRequestorKeys(): KeyPair {
        return this.requestorKeys;
    }

}
