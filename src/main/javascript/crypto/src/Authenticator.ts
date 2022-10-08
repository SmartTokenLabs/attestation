import {Ticket} from "./Ticket";
import {KeyPair, keysArray} from "./libs/KeyPair";
import {base64ToUint8array, uint8ToBn, uint8tohex, uint8toString, logger, hexStringToBase64Url,
hexStringToBase64} from "./libs/utils";
import {SignedIdentifierAttestation} from "./libs/SignedIdentifierAttestation";
import {AttestedObject} from "./libs/AttestedObject";
import {AttestationCrypto} from "./libs/AttestationCrypto";
import {AttestationRequest} from "./libs/AttestationRequest";
import {Nonce} from "./libs/Nonce";
import {Eip712AttestationRequest} from "./libs/Eip712AttestationRequest";
import {IdentifierAttestation} from "./libs/IdentifierAttestation";
import {SignatureUtility} from "./libs/SignatureUtility";
import {FullProofOfExponent} from "./libs/FullProofOfExponent";
import {UseAttestation} from "./libs/UseAttestation";
import {Eip712AttestationUsage} from "./libs/Eip712AttestationUsage";
import {Verifiable} from "./libs/Verifiable";
import {TokenValidateable} from "./libs/TokenValidateable";
import {Eip712AttestationRequestWithUsage} from "./libs/Eip712AttestationRequestWithUsage";
import {AttestationRequestWithUsage} from "./libs/AttestationRequestWithUsage";
import {Validateable} from "./libs/Validateable";
import {DEBUGLEVEL} from "./config";
import {UseToken} from "./asn1/shemas/UseToken";

let subtle:any;

if (typeof crypto === "object" && crypto.subtle){
    subtle = crypto.subtle;
} else {
    subtle = require('crypto').webcrypto.subtle;
}

const ALPHA_CONFIG = {
    indexedDBname: "AlphaDB",
    indexedDBobject: "AlphaKeyStore",
    indexedDBid: "TK",
    keysAlgorithm: {
        name: "ECDSA",
        // namedCurve: "P-384"
        namedCurve: "P-256"
    },
    signAlgorithm: {
        name: "ECDSA",
        // hash: {name: "SHA-384"},
        hash: {name: "SHA-256"},
    }
};



export interface TicketValidate {
    valid: boolean,
    ticketId?: string,
    ticketClass?: number,
    massage?: string
}

export class Authenticator {

    static decodePublicKey(file: string) {
        return KeyPair.publicFromBase64orPEM(file);
    }

    // TODO: Pass in Ticket schema object
    static async getUseTicket(
        ticketSecret: bigint,
        attestationSecret: bigint,
        base64ticket: string,
        base64attestation: string,
        base64attestationPublicKey: string,
        base64senderPublicKeys: {[key: string]: KeyPair|KeyPair[]|string}
    )
    {
        let ticket: Ticket;
        let att: SignedIdentifierAttestation;
        try {
            base64senderPublicKeys = KeyPair.parseKeyArrayStrings(base64senderPublicKeys);
        } catch(e){
            logger(DEBUGLEVEL.LOW, e);
            throw new Error("Issuer key error");
        }

        if (!base64ticket) {
            throw new Error("Ticket is empty");
        }

        ticket = Ticket.fromBase64(base64ticket, <keysArray>base64senderPublicKeys);

        if (!ticket.checkValidity()) {
            logger(DEBUGLEVEL.LOW,"Could not validate ticket");
            throw new Error("Ticket Validation failed");
        }

        if (!ticket.verify()) {
            logger(DEBUGLEVEL.LOW,"Could not verify ticket");
            throw new Error("Ticket Verification failed");
        }

        logger(DEBUGLEVEL.MEDIUM,'ticked valid (signature OK)');
        

        if (!base64attestationPublicKey) {
            throw new Error("Attesator key not defined");
        }

        let attestorKey;
        try {
            attestorKey = KeyPair.publicFromBase64orPEM(base64attestationPublicKey);
        } catch (e) {
            throw new Error("Attesator key read error");
        }

        try {
            att = SignedIdentifierAttestation.fromBytes(base64ToUint8array(base64attestation), attestorKey);
        } catch (e) {
            throw new Error("IDAttestation decode error");
        }


        if (!att.checkValidity()) {
            throw new Error("IDAttestation Validation failed");
        }
        if (!att.verify()) {
            throw new Error("IDAttestation Verification failed");
        }
        logger(DEBUGLEVEL.HIGH,'attestation valid');
        
        try {
            let redeem: AttestedObject = new AttestedObject();
            redeem.create(ticket, att,
                BigInt(attestationSecret), BigInt(ticketSecret));

            let unSigned = redeem.getDerEncoding();

            logger(DEBUGLEVEL.HIGH, unSigned);
            return hexStringToBase64(unSigned);
            // return unSigned;

        } catch (e) {
            logger(DEBUGLEVEL.MEDIUM,'getUseTicket: redeem failed',e);
            throw new Error("Attestation doesnt fit Ticket: " + e.message);
        }


    }

    // TODO: Pass in Ticket schema object
    static validateUseTicket(proof:string, base64attestorPublicKey:string, base64issuerPublicKeys: {[key: string]: KeyPair|string}, userEthKey: string|null){

        let attestorKey = KeyPair.publicFromBase64orPEM(base64attestorPublicKey);
        let issuerKeys = KeyPair.parseKeyArrayStrings(base64issuerPublicKeys);

        try {
            let decodedAttestedObject = AttestedObject.fromBytes(base64ToUint8array(proof), UseToken, attestorKey, Ticket, issuerKeys);

            logger(DEBUGLEVEL.LOW,"Verified attested object");

            if (!decodedAttestedObject.checkValidity(userEthKey)){
                throw new Error("Ticket validity check failed!");
            }

			return decodedAttestedObject;

        } catch (e) {
            let message = "Ticket proof validation failed! " + e.message;
            logger(DEBUGLEVEL.MEDIUM, message);
            throw new Error(message);
        }

    }

    /*
     * get ticket attestation from wallet, or issuer site's local storage through iframe
     *  - Open an Iframe and obtain the data object (in this case SignedDevonTicket)
     */
    // function

    // getTokenAttestation(tokenObj) {
    // }

    static async requestAttest( receiverId: string, type: string, attestorDomain: string, secret: bigint, userKey: KeyPair = null ){

        let crypto = new AttestationCrypto();
        let userAddress;
        if (userKey) {
            userAddress = userKey.getAddress();
        } else {
            try {
                userAddress = await SignatureUtility.connectMetamaskAndGetAddress();
            } catch (e){
                logger(DEBUGLEVEL.LOW,'Cant find user Ethereum Address. Please check Metamask. ' + e);
                logger(DEBUGLEVEL.MEDIUM,e);
                return;
            }
        }

        let nonce = await Nonce.makeNonce(userAddress, attestorDomain);
        logger(DEBUGLEVEL.HIGH,'nonce = ' + uint8tohex(nonce));

        let pok = crypto.computeAttestationProof(secret, nonce);
        let attRequest = AttestationRequest.fromData(crypto.getType(type), pok);
        let attestationRequest = new Eip712AttestationRequest(userKey);
        // undefined means that we will use default value in attestationRequest.addData() second parameter
        await attestationRequest.addData(attestorDomain, undefined, receiverId, attRequest);

        Authenticator.checkAttestRequestVerifiability(attestationRequest);
        Authenticator.checkAttestRequestValidity(attestationRequest);

        let attestJson = attestationRequest.getJsonEncoding();

        return attestJson;

    }

    // static async constructAttest(
    //     attestorKey: KeyPair,
    //     receiverId: string,
    //     type: string,
    //     ATTESTOR_DOMAIN: string,
    //     attestationSecretBase64: string,
    //     sessionKey: KeyPair,
    // ){
    //
    // }

    static constructAttest(
        attestorKey: KeyPair,
        issuerName: string,
        validityInMilliseconds: number ,
        attestRequestJson: string,
        attestorDomain: string,
        usageValue: string = "" ){
        let att: IdentifierAttestation;
        let crypto = new AttestationCrypto();
        let attestationRequest;
        let commitment;

        try {
            // decode JSON and fill publicKey
            // set usageValue as "Creating email attestation"
            attestationRequest = new Eip712AttestationRequest();
            attestationRequest.setDomain(attestorDomain);
            if (usageValue){
                attestationRequest.setUsageValue(usageValue);
            }
            attestationRequest.fillJsonData(attestRequestJson);

            Authenticator.checkAttestRequestVerifiability(attestationRequest);
            Authenticator.checkAttestRequestValidity(attestationRequest);

        } catch (e){
            let m = "Failed to fill attestation data from json. " + e + "\nRestores as an Eip712AttestationRequestWithUsage object instead";
            logger(DEBUGLEVEL.MEDIUM,m);
            try {
                attestationRequest = new Eip712AttestationRequestWithUsage();
                attestationRequest.setDomain(attestorDomain);
                attestationRequest.fillJsonData(attestRequestJson);
                Authenticator.checkAttestRequestVerifiability(attestationRequest);
                Authenticator.checkAttestRequestValidity(attestationRequest);
            } catch (e) {
                let m = "Failed to parse Eip712AttestationRequestWithUsage. " + e;
                logger(DEBUGLEVEL.LOW,m);
                logger(DEBUGLEVEL.MEDIUM,e);
                throw new Error(m);
            }
        }

        commitment = crypto.makeCommitmentFromHiding(attestationRequest.getIdentifier(), attestationRequest.getType(), attestationRequest.getPok().getRiddle());

        att = new IdentifierAttestation();
        att.fromCommitment(commitment, attestationRequest.getUserPublicKey());
        att.setIssuer("CN=" + issuerName);
        att.setSerialNumber(Math.round(Math.random() * Number.MAX_SAFE_INTEGER) );
        let now = Date.now();
        att.setNotValidBefore(now);
        att.setNotValidAfter(now + validityInMilliseconds);
        let signed: SignedIdentifierAttestation = SignedIdentifierAttestation.fromData(att, attestorKey);
        return signed.getDerEncoding();
    }

    // PREFIX + "user-priv.pem", PREFIX + "attestation.crt", PREFIX + "attestation-secret.pem", PREFIX + "attestor-pub.pem", "test@test.ts", "mail", PREFIX + "session-priv.pem", PREFIX + "use-attestation.json"
    static async useAttest(
        attestationBase64: string,
        attestationSecretBase64: string ,
        attestorKey: KeyPair,
        receiverId: string,
        type: string,
        webDomain: string,
        sessionKey: KeyPair = null,
        userKey: KeyPair = null){



        const attestationUint8 = base64ToUint8array(attestationBase64);
        let att = SignedIdentifierAttestation.fromBytes(attestationUint8, attestorKey);
        let attestationSecretDerUint8 = base64ToUint8array(attestationSecretBase64);
        // remove first 4 bytes because us der encoding
        let attestationSecret = uint8ToBn(attestationSecretDerUint8.slice(4));

        let crypto = new AttestationCrypto();

        let address;
        if (userKey) {
            address = userKey.getAddress();
        } else {
            address = await SignatureUtility.connectMetamaskAndGetAddress();
        }

        let nonce = await Nonce.makeNonce(address, webDomain);

        let pok: FullProofOfExponent = crypto.computeAttestationProof(attestationSecret, nonce);

        try {
            let attUsage: UseAttestation = UseAttestation.fromData(att, crypto.getType(type), pok, sessionKey);
            let usageRequest: Eip712AttestationUsage = new Eip712AttestationUsage(userKey);
            let res = await usageRequest.addData(webDomain, receiverId, attUsage);
            logger(DEBUGLEVEL.HIGH, 'usageRequest ready state = ' + res);
            logger(DEBUGLEVEL.HIGH, 'usageRequest.getJsonEncoding() = ' + usageRequest.getJsonEncoding());
            return usageRequest.getJsonEncoding();
        } catch (e) {
            logger(DEBUGLEVEL.LOW,e);
        }

    }

    static checkAttestRequestVerifiability( input:Verifiable) {
        if (!input.verify()) {
            logger(DEBUGLEVEL.MEDIUM,"Could not verify attestation signing request");
            throw new Error("Verification failed");
        }
    }

    static checkAttestRequestValidity( input:Validateable) {
        if (!input.checkValidity()) {
            logger(DEBUGLEVEL.HIGH,"Could not validate attestation signing request");
            throw new Error("Validation failed");
        }
    }

    static checkUsageVerifiability(input: Verifiable) {
        if (!input.verify()) {
            logger(DEBUGLEVEL.LOW,"Could not verify usage request");
            throw new Error("Verification failed");
        }
    }

    static checkUsageValidity( input: TokenValidateable) {
        if (!input.checkTokenValidity()) {
            logger(DEBUGLEVEL.LOW,"Could not validate usage request");
            throw new Error("Validation failed");
        }
    }

    static async verifyUsage(
        jsonRequest: string,
        attestorKey: KeyPair,
        message: string,
        WEB_DOMAIN: string,
        signature: Uint8Array){

        let sessionPublicKey: KeyPair;

        try {
            let usageRequest: Eip712AttestationUsage = new Eip712AttestationUsage();
            usageRequest.setDomain(WEB_DOMAIN);
            usageRequest.fillJsonData( jsonRequest, attestorKey);
            Authenticator.checkUsageVerifiability(usageRequest);
            Authenticator.checkUsageValidity(usageRequest);
            sessionPublicKey = usageRequest.getSessionPublicKey();
        } catch (e) {
            // Try as an  Eip712AttestationRequestWithUsage object instead, which is NOT linked to a specific website
            logger(DEBUGLEVEL.MEDIUM,'Eip712AttestationUsage failed. ' + e + '. Lets try to verify Eip712AttestationRequestWithUsage');
            let usageRequest: Eip712AttestationRequestWithUsage = new Eip712AttestationRequestWithUsage();
            usageRequest.setDomain(WEB_DOMAIN);
            usageRequest.fillJsonData( jsonRequest );
            Authenticator.checkUsageVerifiability(usageRequest);

            Authenticator.checkUsageValidity(usageRequest);
            sessionPublicKey = usageRequest.getSessionPublicKey();
            logger(DEBUGLEVEL.HIGH, 'sessionPublicKey from Eip712AttestationRequestWithUsage = '+ sessionPublicKey.getAddress());
        }

        // Validate signature
        try {
            let res = await sessionPublicKey.verifyStringWithSubtle(KeyPair.anySignatureToRawUint8(signature) , message);
            if (!res) {
                logger(DEBUGLEVEL.MEDIUM,"Could not verify message signature");
                throw new Error("Signature verification failed");
            }
             return "SUCCESSFULLY validated usage request!";
        } catch (e) {
            let m = "Cant verify session with subtle. " + e;
            logger(DEBUGLEVEL.LOW,m);
            logger(DEBUGLEVEL.MEDIUM,e);
        }
    }

    static async requestAttestAndUsage(
        userKey: KeyPair,
        receiverId: string,
        type: string,
        ATTESTOR_DOMAIN: string,
        attestationSecretBase64: string,
        sessionKey: KeyPair,
        ){
        try {
            let attestationSecret = uint8ToBn(base64ToUint8array(attestationSecretBase64));

            let address;
            if (userKey) {
                address = userKey.getAddress();
            } else {
                address = await SignatureUtility.connectMetamaskAndGetAddress();
            }

            let nonce: Uint8Array = await Nonce.makeNonce(address, ATTESTOR_DOMAIN, new Uint8Array(0), Date.now());
            let crypto = new AttestationCrypto();

            let pok: FullProofOfExponent = crypto.computeAttestationProof(attestationSecret, nonce);

            let attRequest: AttestationRequestWithUsage =  AttestationRequestWithUsage.fromData(crypto.getType(type), pok, sessionKey);
            let request: Eip712AttestationRequestWithUsage = new Eip712AttestationRequestWithUsage(userKey);
            await request.fromData(ATTESTOR_DOMAIN, undefined, undefined, receiverId, attRequest);
            logger(DEBUGLEVEL.HIGH, 'request.getJsonEncoding() = ' + request.getJsonEncoding());
            return request.getJsonEncoding();
        } catch (e) {
            let m = "requestAttestAndUsage error. " + e;
            logger(DEBUGLEVEL.LOW,m);
            logger(DEBUGLEVEL.MEDIUM,e);
        }

    }


/*
    static async signMessageWithSessionKey(message: Uint8Array, sessionKey: Uint8Array = new Uint8Array(0)){
        let privKey, signature;
        // logger(DEBUGLEVEL.HIGH, "message = " + uint8tohex(message));

        try {
            if (sessionKey && sessionKey.length) {
                // its nodejs and session primary key received in Uint8Array
                logger(DEBUGLEVEL.HIGH, "sessionKey = " + uint8tohex(sessionKey));
                logger(DEBUGLEVEL.HIGH, sessionKey);

            } else {
                // TODO read key from local storage
            }
            // signature = await crypto.subtle.sign(ALPHA_CONFIG.signAlgorithm, privKey, message);
        } catch (e){
            logger(DEBUGLEVEL.HIGH, e);
            // throw new Error(e);
        }
        // let signatureHex = uint8tohex(new Uint8Array(signature));
        // return signatureHex;
    }

    static async verifyMessageSignatureWithSessionKey(message: Uint8Array, signature: string, sessionKey: Uint8Array = new Uint8Array(0)){
        let privKey;
        if (sessionKey && sessionKey.length) {
            // its nodejs and session primary key received in Uint8Array
            privKey = await subtle.importKey(
                'raw',
                sessionKey,
                {
                    name: "ECDSA",
                    namedCurve: "P-256"
                },
                true,
                ['sign', 'verify']
            );
        } else {
            // TODO read key from local storage
        }

        let signatureUint8 = hexStringToUint8(signature);

        const result = await crypto.subtle.verify(ALPHA_CONFIG.keysAlgorithm, privKey.publicKey, signatureUint8, message );
    }

 */

    
    static validateTicket(ticketBase64: string, confernceId: string,  publicKeyPEM: string): TicketValidate{
        let keys: keysArray = {};
        
        try {
            keys[confernceId] = KeyPair.parseKeyArrayStrings({[confernceId]: publicKeyPEM})[confernceId];
        } catch(e){
            return {
                valid: false,
                massage: "Broken Public Key"
            }
        }

        let ticket;
        try {
            ticket = Ticket.fromBase64(ticketBase64, keys);
        } catch(e) {
            logger(DEBUGLEVEL.LOW, e);
            return {
                valid: false,
                massage: "Wrong Ticket"
            }
        }

        return {
            valid: true,
            ticketId: ticket.getTicketId(),
            ticketClass: ticket.getTicketClass(),
        }
    }
}
