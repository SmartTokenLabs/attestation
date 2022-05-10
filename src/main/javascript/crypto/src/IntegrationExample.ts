import {XMLconfigData} from "./data/tokenData";
import {logger} from "./libs/utils";
import {DEBUGLEVEL} from "./config";
import {Authenticator} from "./Authenticator";
import {KeyPair} from "./libs/KeyPair";

declare global {
    interface Window {
        attachEvent: any;
        detachEvent: any;
    }
}

export interface devconToken {
    ticketBlob: string,
    ticketSecret: bigint,
    email?: string,
    magicLink?: string,
    attestationOrigin: string,
}

interface postMessageData {
    force?: boolean,
    email?: string,
    magicLink?: string,
}

export class IntegrationExample {
    private signedTokenBlob: string;
    private signedTokenSecret: bigint;

    private attestationBlob: string;
    private attestationSecret: bigint;

    private magicLink: string;
    private email: string;

    private attestationOrigin: string;
    private authResultCallback: Function;

    private iframe: any;
    private iframeWrap: any;
    private base64senderPublicKeys: { [key: string]: KeyPair };
    private base64attestorPubKey: string;

    private webDomain: string;

    constructor(private negotiator: any = false) {
        let XMLconfig = XMLconfigData;

        this.base64senderPublicKeys = XMLconfig.base64senderPublicKeys;
        this.base64attestorPubKey = XMLconfig.base64attestorPubKey;
        this.webDomain = XMLconfig.webDomain;
    }

    getAuthenticationBlob(tokenObj: devconToken, authResultCallback: Function) {
        // TODO - what is tokenType, where can we see structure etc.
        // 1. Find the token type (using TokenScript)
        // Oleg: we can avoid Autenticator -> Negotiator request, just have to receive everything in single input object
        // let tokenType = Negotiator.getTokenType(tokenObj.tokenClass);
        // 2. Trace from its TokenScript which website has the needed data object
        // if (tokenType.attestationOrigin) { // always return true in Devcon project,
        // unless DevCon changed their tokenscript and moved all tickets to the contract

        this.signedTokenBlob = tokenObj.ticketBlob;
        this.magicLink = tokenObj.magicLink;
        this.email = tokenObj.email;
        this.signedTokenSecret = tokenObj.ticketSecret;
        this.attestationOrigin = tokenObj.attestationOrigin;
        this.authResultCallback = authResultCallback;
        this.getIdentifierAttestation();

    }

    /*
     *  - Since this token depends on identifier attestation, continue to open iframe to attestation.id who needs to provide the proof
     */
    getIdentifierAttestation() {
        logger(DEBUGLEVEL.HIGH,'getIdentifierAttestation. create iframe with ' + this.attestationOrigin);

        // attach postMessage listener and wait for attestation data
        this.attachPostMessageListener(this.postMessageAttestationListener.bind(this));
        const iframe = document.createElement('iframe');
        this.iframe = iframe;
        iframe.src = this.attestationOrigin;
        iframe.style.width = '800px';
        iframe.style.height = '700px';
        iframe.style.maxWidth = '100%';
        iframe.style.background = '#fff';
        let iframeWrap = document.createElement('div');
        this.iframeWrap = iframeWrap;
        iframeWrap.setAttribute('style', 'width:100%;min-height: 100vh; position: fixed; align-items: center; justify-content: center;display: none;top: 0; left: 0; background: #fffa');
        iframeWrap.appendChild(iframe);

        document.body.appendChild(iframeWrap);
    }

    postMessageAttestationListener(event: MessageEvent){
        let attestURL = new URL(this.attestationOrigin);

        if (event.origin !== attestURL.origin) {
            return;
        }

        logger(DEBUGLEVEL.HIGH,'postMessageAttestationListener event (Authenticator)',event);

        if (
            typeof event.data.ready !== "undefined"
            && event.data.ready === true
        ) {
            let sendData:postMessageData = {force: false};
            if (this.magicLink) sendData.magicLink = this.magicLink;
            if (this.email) sendData.email = this.email;

            this.iframe.contentWindow.postMessage(sendData, this.attestationOrigin);
            return;
        }


        if (
            typeof event.data.display !== "undefined"
        ) {
            if (event.data.display === true) {
                this.iframeWrap.style.display = 'flex';
                this.negotiator && this.negotiator.commandDisplayIframe();
            } else {

                if (event.data.error){
                    logger(DEBUGLEVEL.LOW, "Error received from the iframe: " + event.data.error);
                    this.authResultCallback(null, event.data.error);
                }

                this.iframeWrap.style.display = 'none';
                this.negotiator && this.negotiator.commandHideIframe();

            }
        }

        if (
            !event.data.hasOwnProperty('attestation')
            || !event.data.hasOwnProperty('requestSecret')
        ) {
            return;
        }
        this.iframeWrap.remove();
        this.attestationBlob = event.data.attestation;
        this.attestationSecret = event.data.requestSecret;

        logger(DEBUGLEVEL.HIGH,'attestation data received.');
        logger(DEBUGLEVEL.HIGH,this.attestationBlob);
        logger(DEBUGLEVEL.HIGH,this.attestationSecret);
        logger(DEBUGLEVEL.HIGH,this.base64attestorPubKey);

        try {
            Authenticator.getUseTicket(
                this.signedTokenSecret,
                this.attestationSecret,
                this.signedTokenBlob ,
                this.attestationBlob ,
                this.base64attestorPubKey,
                this.base64senderPublicKeys,
            ).then(useToken => {
                if (useToken){
                    logger(DEBUGLEVEL.HIGH,'this.authResultCallback( useToken ): ');
                    this.authResultCallback(useToken);
                } else {
                    logger(DEBUGLEVEL.HIGH,'this.authResultCallback( empty ): ');
                    this.authResultCallback(useToken);
                }

            })


        } catch (e){
            logger(DEBUGLEVEL.LOW,`UseDevconTicket. Something went wrong. ${e}`);
            this.authResultCallback(false);
        }
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

    attachPostMessageListener(listener: Function){
        if (window.addEventListener) {
            window.addEventListener("message", (e) => {
                listener(e);
            }, false);
        } else {
            // IE8
            window.attachEvent("onmessage", (e: MessageEvent) => {
                listener(e);
            });
        }
    }

}