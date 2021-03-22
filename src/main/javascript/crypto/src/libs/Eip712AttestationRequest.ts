import {Eip712Validator} from "./Eip712Validator";
import {Validateable} from "./Validateable";
import {Verifiable} from "./Verifiable";
import {JsonEncodable} from "../intefaces/JsonEncodable";
import {AttestationRequest} from "./AttestationRequest";
import {KeyPair} from "./KeyPair";
import {FullProofOfExponent} from "./FullProofOfExponent";
import {SignatureUtility} from "./SignatureUtility";
import {base64ToUint8array, hexStringToBase64Url} from "./utils";
import {Nonce} from "./Nonce";
import {Eip712Token} from "./Eip712Token";

export class Eip712AttestationRequest extends Eip712Token implements JsonEncodable, Verifiable, Validateable {
    private jsonEncoding: string;
    private attestationRequest: AttestationRequest;


    private Eip712UserDataTypes: {name: string, type: string}[]  = [
        {name: 'address', type: 'string'},
        {name: 'description', type: 'string'},
        {name: 'identifier', type: 'string'},
        {name: 'payload', type: 'string'},
        {name: 'timestamp', type: 'string'},
    ]
    private Eip712UserDataPrimaryName: string = "AttestationRequest";
    private Eip712UserDataDescription: string = "Linking Ethereum address to phone or email";

    async addData(attestorDomain: string, identifier: string, request: AttestationRequest) {
        this.setDomainAndTimout(attestorDomain);

        // this.attestationRequest = AttestationRequest.fromData(type,pok);
        this.attestationRequest = request;

        this.jsonEncoding = await this.makeToken(identifier);

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
            description: this.Eip712UserDataDescription,
            timestamp: ts,
            identifier: identifier,
            address: userAddress,
        };


        return await SignatureUtility.signEIP712WithBrowserWallet(this.domain, userData, this.Eip712UserDataTypes, this.Eip712UserDataPrimaryName );
    }

    setAcceptableTimeLimit(limit: number){
        this.acceptableTimeLimitMs = limit;
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

        if (this.data.description !== this.Eip712UserDataDescription) {
            console.log('Description is not correct');
            return false;
        };

        if (!this.verifyTimeStamp(this.data.timestamp)) {
            console.log('Timelimit expired');
            return false;
        };

        if (this.requestorKeys.getAddress().toLowerCase() !== this.data.address.toLowerCase()) {
            console.log('Keys doesnt fit');
            return false;
        };

        if (! (new Nonce().validateNonce(this.getPok().getNonce(), this.getIdentifier(), this.data.address, this.domain, this.acceptableTimeLimitMs))) {
            console.log('Nonce check failed');
            return false;
        };
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

    public getRequestorKeys(): KeyPair {
        return this.requestorKeys;
    }

}
