import {Eip712Validator} from "./Eip712Validator";
import {JsonEncodable} from "../intefaces/JsonEncodable";
import {Verifiable} from "./Verifiable";
import {Validateable} from "./Validateable";
import {UseAttestation} from "../asn1/shemas/UseAttestation";
import {KeyPair} from "./KeyPair";
import {base64toBase64Url, hexStringToArray, uint8arrayToBase64} from "./utils";
import {SignatureUtility} from "./SignatureUtility";

export class Eip712AttestationUsage extends Eip712Validator implements JsonEncodable, Verifiable,
    Validateable {
    public PLACEHOLDER_CHAIN_ID: number = 0;
    public Eip712PrimaryName: string = "AttestationUsage";
    public Eip712Description: string = "Prove that the \"identity\" is the identity hidden in attestation contained in\"payload\".";
    public Eip712Types: {name: string, type: string}[]  = [
        {name: 'description', type: 'string'},
        {name: 'identifier', type: 'string'},
        {name: 'payload', type: 'string'},
        // {name: 'timestamp', type: 'uint256'},
        {name: 'timestamp', type: 'string'},
    ]

    private useAttestation: string;
    // TODO fix any
    private data: any;
    private jsonEncoding: string;
    private userPublicKey: KeyPair;

    public async addData(attestorDomain: string, identifier: string, useAttestation: string, signingKey: KeyPair, acceptableTimeLimit: number = this.DEFAULT_TIME_LIMIT_MS) {
        this.setDomainAndTimout(attestorDomain, acceptableTimeLimit);

        try {
            this.useAttestation = useAttestation;
            this.jsonEncoding = await this.makeToken(identifier, useAttestation, signingKey);
            // TODO
            //this.userPublicKey = this.retrieveUserPublicKey(jsonEncoding);
            //this.data = this.retrieveUnderlyingObject(jsonEncoding);
        } catch ( e ) {
            throw new Error("Could not encode object");
        }
        // TODO
        // this.constructorCheck();
    }

    // use Att
    async makeToken(identifier: string, useAttestationBase64UrlEncoded: string, signingKey: KeyPair): Promise<string>{
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
            payload: useAttestationBase64UrlEncoded,
            description: this.Eip712Description,
            // timestamp: new Date().getTime(),

            // TODO fix hardcoded timezone
            // timestamp: Date.now().toString("yyyy.MM.dd HH:mm:ss 000 EET"),
            timestamp: Date.now().toString(),
            // timestamp: "yyyy.MM.dd HH:mm:ss 000 EET",
            identifier: identifier,
            address: userAddress[0],
        };


        return await SignatureUtility.signEIP712WithBrowserWallet(this.domain, userData, this.Eip712Types, this.Eip712PrimaryName );
    }

    // TODO
    getJsonEncoding(): string {
        return '';
    }

    // TODO
    checkValidity(): boolean {
        return false;
    }

    //TODO
    verify(): boolean {
        return false;
    }
}
