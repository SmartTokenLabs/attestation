import {JsonEncodable} from "../intefaces/JsonEncodable";
import {Verifiable} from "./Verifiable";
import {Validateable} from "./Validateable";
import {KeyPair} from "./KeyPair";
import {SignatureUtility} from "./SignatureUtility";
import {Eip712Token} from "./Eip712Token";
import {UseAttestation} from "./UseAttestation";
import {base64ToUint8array, hexStringToBase64Url} from "./utils";
import {AttestationCrypto, Pedestren_G} from "./AttestationCrypto";
import {CURVE_BN256, Point} from "./Point";
import {FullProofOfExponent} from "./FullProofOfExponent";
import {Nonce} from "./Nonce";

export class Eip712AttestationUsage extends Eip712Token implements JsonEncodable, Verifiable,
    Validateable {
    public PLACEHOLDER_CHAIN_ID: number = 0;
    public DEFAULT_TOKEN_TIME_LIMIT = 1000 * 60 * 60 * 24 * 7; // 1 week
    public Eip712PrimaryName: string = "AttestationUsage";
    public Eip712Description: string = "Prove that the \"identity\" is the identity hidden in attestation contained in\"payload\".";
    public Eip712UserTypes: {name: string, type: string}[]  = [
        {name: 'description', type: 'string'},
        {name: 'identifier', type: 'string'},
        {name: 'payload', type: 'string'},
        {name: 'timestamp', type: 'string'},
    ]

    private useAttestation: UseAttestation;
    private jsonEncoding: string;
    private attestorKey: KeyPair;
    private tokenValidityInMs: number;

    public async addData(attestorDomain: string, identifier: string, useAttestation: UseAttestation, signingKey: KeyPair, acceptableTimeLimit: number = this.DEFAULT_TIME_LIMIT_MS, tokenValidityInMs:number = this.DEFAULT_TOKEN_TIME_LIMIT) {
        this.setDomainAndTimout(attestorDomain, acceptableTimeLimit);
        this.tokenValidityInMs = tokenValidityInMs;
        this.useAttestation = useAttestation;

        try {
            this.jsonEncoding = await this.makeToken(identifier, useAttestation, signingKey);
        } catch ( e ) {
            throw new Error("Could not encode object");
        }

        try {
            // decode JSON and fill publicKey
            this.fillJsonData(this.jsonEncoding);
        } catch (e){
            console.log(e);
            return false;
        }

        this.constructorCheck();
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

        if (!this.useAttestation){
            this.useAttestation = UseAttestation.fromBytes(base64ToUint8array( this.data.payload), this.attestorKey);
        }

        this.constructorCheck();
    }

    constructorCheck() {
        if (!this.verify()) {
            throw new Error("Could not verify Eip712 use attestation");
        }
    }

    // use Att
    async makeToken(identifier: string, useAttestation: UseAttestation, signingKey: KeyPair = null): Promise<string>{
        let userAddress = await SignatureUtility.connectMetamaskAndGetAddress();

        let userData = {
            payload: hexStringToBase64Url(useAttestation.getDerEncoding()),
            description: this.Eip712Description,
            timestamp: Date.now().toString(),
            identifier: identifier,
            address: userAddress,
        };

        return await SignatureUtility.signEIP712WithBrowserWallet(this.domain, userData, this.Eip712UserTypes, this.Eip712PrimaryName );
    }

    proofLinking() {
        let crypto = new AttestationCrypto();
        let candidateExponent = crypto.mapToCurveMultiplier(this.getType(), this.getIdentifier());
        let commitmentPoint: Point = Point.decodeFromUint8(this.getAttestation().getUnsignedAttestation().getCommitment());
        let candidateRiddle: Point = commitmentPoint.subtract(Pedestren_G.multiplyDA(candidateExponent));
        if (!candidateRiddle.equals(this.getPok().getRiddle())) {
            return false;
        }
        return true;
    }

    getPok(): FullProofOfExponent{
        return this.useAttestation.getPok();
    }

    getType(): number {
        return this.useAttestation.type;
    }

    getIdentifier(): string {
        return this.data.identifier;
    }

    getAttestation(){
        return this.useAttestation.getAttestation();
    }

    getJsonEncoding(): string {
        return this.jsonEncoding;
    }

    checkValidity(): boolean {
        if (!this.useAttestation.checkValidity()){
            console.log('useAttestation.checkValidity failed');
            return false;
        };

        if (this.data.description != this.Eip712Description) {
            console.log('wrong description');
            return false;
        };

        if (this.verifyTimeStamp(this.data.timestamp)) {
            console.log('verify timestamp failed');
            return false;
        };

        if (this.requestorKeys.getAddress().toLowerCase() !== this.useAttestation.getAttestation().getUnsignedAttestation().getAddress().toLowerCase()) {
            console.log('wrong address');
            return false;
        };

        if (!(new Nonce().validateNonce(this.useAttestation.getPok().getNonce(), this.data.identifier,
            (this.useAttestation.getAttestation().getUnsignedAttestation()).getAddress(), this.domain, this.acceptableTimeLimitMs))) {
            console.log('wrong Nonce');
            return false;
        };

        if (!this.proofLinking()) {
            console.log('wrong proofLinking');
            return false;
        };
        return true;
    }


    verify(): boolean {
        if (!this.useAttestation.verify()) {
            return false;
        }
        // Remove the "CN=" prefix of subject to get the address
        let address:string = this.useAttestation.getAttestation().getUnsignedAttestation().getAddress();
        if (!this.verifySignature(this.jsonEncoding, address)) {
            return false;
        }
        return true;
    }

}
