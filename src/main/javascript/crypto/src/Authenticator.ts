import {AttestationRequest, attestationRequestData} from "./libs/AttestationRequest";
import {AttestedObject} from "./libs/AttestedObject";

export interface attestationResult {
    attestation?: string,
    attestationSecret?: bigint
}

declare global {
    interface Window {
        attachEvent: any;
    }
}

interface devconToken {
    ticketBlob: string,
    ticketSecret: bigint,
    attestationOrigin: string,
}

export class Authenticator {
    private signedTokenBlob: string;
    private signedTokenSecret: bigint;

    private attestationBlob: string;
    private attestationSecret: bigint;

    private attestationOrigin: string;
    private authResultCallback: Function;
    // attestRequest: string;

    // create crypto hiding of the secret for identifier(email) attestation
    // createIdentifierAttestationRequest(email: string):attestationRequestData {
    //     let requestAndSecret:attestationRequestData;
    //     try {
    //         requestAndSecret = AttestationRequest.fromEmail(email);
    //         if (!requestAndSecret.request || !requestAndSecret.requestSecret) throw new Error("Empty requestAttestData");
    //     } catch (e) {
    //         console.error(e);
    //         return {} as attestationRequestData;
    //     }
    // }

    // attestIdentifierRequest(request:string){
    //     this.attestRequest = requestAndSecret.request;
    //     this.saveAttestRequestSecret(requestAndSecret.requestSecret);
    //     this.openAttestorIframe(Authenticator.initData.attestor);
    // }

    // saveAttestRequestSecret (secret: bigint) {
    //     // TODO save encrypted secret to LocalStorage
    // }

    getAuthenticationBlob(tokenObj: devconToken, authResultCallback: Function) {
        // TODO - what is tokenType, where can we see structure etc.
        // 1. Find the token type (using TokenScript)
        // Oleg: we can avoid Autenticator -> Negotiator request, just have to receive everything in single input object
        // let tokenType = Negotiator.getTokenType(tokenObj.tokenClass);
        // 2. Trace from its TokenScript which website has the needed data object
        // if (tokenType.attestationOrigin) { // always return true in Devcon project,
        // unless DevCon changed their tokenscript and moved all tickets to the contract

        this.signedTokenBlob = tokenObj.ticketBlob;
        this.signedTokenSecret = tokenObj.ticketSecret;
        this.attestationOrigin = tokenObj.attestationOrigin;
        this.authResultCallback = authResultCallback;
        this.getIdentifierAttestation();
        // const proof = this.generateIdentifierAttestationProof(identifierAttestation);
        // construct UseDevconTicket, see
        // https://github.com/TokenScript/attestation/blob/main/data-modules/src/UseDevconTicket.asd

        // TODO we dont have ready UseDevconTicket constructor yet
        // let useDevconTicket = new UseDevconTicket({
        //     signedDevconTicket: signedDevonTicket,
        //     identifierAttestation: identifierAttestation,
        //     proof: proof
        // })
        // // Serialise it (for use as a transaction parameter) and return it
        // return useDevconTicket.serialize();
    }

    /*
     *  - Since this token depends on identifier attestation, continue to open iframe to attestation.id who needs to provide the proof
     */
    getIdentifierAttestation() {
        // waitForIframeReadyToInteract disabled because
        // this.attachPostMessageListener(this.postMessageReadyListener);
        this.attachPostMessageListener(this.postMessageAttestationListener);
        const iframe = document.createElement('iframe');
        iframe.setAttribute('name', 'attestor');
        iframe.src = this.attestationOrigin;
        document.body.appendChild(iframe);
    }
    postMessageAttestationListener(event: MessageEvent){
        if (typeof event.data.attestation === "undefined"
            || event.origin !== this.attestationOrigin
            || !event.data.attestation
        ) {
            return;
        }
        this.attestationBlob = event.data.attestation;
        this.attestationSecret = event.data.secret;

        this.authResultCallback(this.attestationBlob, this.attestationSecret);
    }

    generateIdentifierAttestationProof(){
        // let useTokenBlob = AttestedObject();
        // return useTokenBlob;
    }

    // postMessageReadyListener(event: MessageEvent){
    //     if (typeof event.data.readyToAttest === "undefined"
    //         || event.origin !== Authenticator.initData.attestor
    //         || event.data.readyToAttest !== "ready"
    //     ) {
    //         return;
    //     }
    //     event.source.postMessage({request: this.attestRequest}, event.origin)
    //     this.attachPostMessageListener(this.postMessageAttestationListener)
    // }

    attachPostMessageListener(listener: Function){
        if (window.addEventListener) {
            window.addEventListener("message", (e) => {
                listener(e);
            });
        } else {
            // IE8
            window.attachEvent("onmessage", (e: MessageEvent) => {
                listener(e);
            });
        }
    }
    // attachPostMessageListenerWithCallback(listener: Function, callback: Function){
    //     if (window.addEventListener) {
    //         window.addEventListener("message", (e) => {
    //             listener(e,callback);
    //         });
    //     } else {
    //         // IE8
    //         window.attachEvent("onmessage", (e: MessageEvent) => {
    //             listener(e,callback);
    //         });
    //     }
    // }
    // TODO do we need that?
    // assertOwnerAddress(token){
    //
    // }

    /*
     * get ticket attestation from wallet, or issuer site's local storage through iframe
     *  - Open an Iframe and obtain the data object (in this case SignedDevonTicket)
     */
    // function

    // getTokenAttestation(tokenObj) {
    // }


}
