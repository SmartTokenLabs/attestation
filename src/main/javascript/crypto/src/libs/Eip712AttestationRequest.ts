import {Eip712Validator} from "./Eip712Validator";
import {Validateable} from "./Validateable";
import {Verifiable} from "./Verifiable";
import {JsonEncodable} from "../intefaces/JsonEncodable";
import {AttestationRequest} from "./AttestationRequest";
import {KeyPair} from "./KeyPair";
import {FullProofOfExponent} from "./FullProofOfExponent";
import {SignatureUtility} from "./SignatureUtility";
import {base64toBase64Url, base64ToUint8array, hexStringToArray, uint8arrayToBase64} from "./utils";
import {TypedDataUtils} from "eth-sig-util";
import {recoverPublicKey} from "ethers/lib/utils";
// import { recoverTypedSignature_v4 } from 'eth-sig-util'

export class Eip712AttestationRequest extends Eip712Validator implements JsonEncodable, Verifiable, Validateable {
    private jsonEncoding: string;
    private attestationRequest: AttestationRequest;
    private acceptableTimeLimit: number = 100000;
    // TODO type it
    private data: any;
    private eip712DomainData: any;

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

    async addData(attestorDomain: string, identifier: string, type: number,
    // pok: FullProofOfExponent, requestorKey: KeyPair) {
    pok: FullProofOfExponent) {
        this.setDomain(attestorDomain);

        this.attestationRequest = AttestationRequest.fromTypeAndPok(type,pok);

        console.log('lets this.makeToken(identifier)');
        this.jsonEncoding = await this.makeToken(identifier);

        console.log('lets fillJsonData');
        try {
            this.fillJsonData(this.jsonEncoding);
        } catch (e){
            console.log(e);
            return false;
        }
    }

    fillJsonData(json: string){
        let tokenData = JSON.parse(json);
        let signatureInHex = tokenData.signatureInHex;

        let jsonSigned = JSON.parse(tokenData.jsonSigned);
        this.eip712DomainData = jsonSigned.domain;
        this.data = jsonSigned.message;

        let publicKey, requestorKeys;

        // console.log('public key should appear here:');
        try {
            publicKey = SignatureUtility.recoverPublicKeyFromTypedMessageSignature(jsonSigned, signatureInHex);
            requestorKeys = KeyPair.fromPublicHex(publicKey.substr(2));
        } catch (e){
            let m = "Recover Address failed with error:" + e;
            console.log(m)
            // throw new Error(m);
            return false;
        }


        if (!this.attestationRequest){
            this.attestationRequest = AttestationRequest.fromBytes(base64ToUint8array( this.data.payload),requestorKeys);
        } else {
            this.attestationRequest.setKeys(requestorKeys);
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

        if (!window.ethereum){
            throw new Error('Please install metamask before.');
        }
        let userAddress = '';
        try {
            // that method doesnt fire metamask connect
            // userAddress = await window.ethereum.request({ method: 'eth_accounts' });
            userAddress = await window.ethereum.enable();
            if (!userAddress || !userAddress.length) throw new Error('Cant see wallet address.');
        } catch (e){
            console.log('Cant see wallet address.');
            throw new Error('Cant see wallet address.');
        }

        let userData = {
            payload: base64toBase64Url(uint8arrayToBase64(new Uint8Array(hexStringToArray(this.attestationRequest.getUnsignedEncoding())))),
            description: Eip712AttestationRequest.Eip712UserDataDescription,
            timestamp: new Date().getTime(),
            identifier: identifier,
            address: userAddress[0],
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
        if (!this.verifyDomainData()) {
            return false;
        }
        return true;
    }

    public verifyDomainData(): boolean{
        return (this.eip712DomainData.name.toLowerCase() === this.getDomain().toLowerCase())
            && (this.eip712DomainData.version === SignatureUtility.Eip712Data['PROTOCOL_VERSION']);
    }

    public checkValidity() {

        return (this.data.description === Eip712AttestationRequest.Eip712UserDataDescription)
         && this.verifyTimeStamp(this.data.timestamp)
         && (this.data.address.toUpperCase() ===
             this.attestationRequest.getKeys().getAddress().toUpperCase());
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

    public getKeys(): KeyPair {
        return this.attestationRequest.getKeys();
    }

}
