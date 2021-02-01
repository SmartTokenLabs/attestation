import {main} from "./index";
import {base64ToUint8array, uint8ToBn} from "./libs/utils";

export interface attestationResult {
    attestation?: string,
    attestationSecret?: bigint
}

declare global {
    interface Window {
        attachEvent: any;
    }
}

export interface devconToken {
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

    private iframe: any;
    private iframeWrap: any;

    private base64attestorPubKey: string =
        // "MIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA/////////////////////////////////////v///C8wRAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHBEEEeb5mfvncu6xVoGKVzocLBwKb/NstzijZWfKBWxb4F5hIOtp3JqPEZV2k+/wOEQio/Re0SKaFVBmcR9CP+xDUuAIhAP////////////////////66rtzmr0igO7/SXozQNkFBAgEBA0IABPxJAMZA6IJIETOGrIVLr11P1Y92OZ6UNyD2OndOMMtdA6s6Z8u7oY3BER4uBEffjk2UF5JI6uCMqUORlVzLfXY=";
        "MIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA/////////////////////////////////////v///C8wRAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHBEEEeb5mfvncu6xVoGKVzocLBwKb/NstzijZWfKBWxb4F5hIOtp3JqPEZV2k+/wOEQio/Re0SKaFVBmcR9CP+xDUuAIhAP////////////////////66rtzmr0igO7/SXozQNkFBAgEBA0IABPxJAMZA6IJIETOGrIVLr11P1Y92OZ6UNyD2OndOMMtdA6s6Z8u7oY3BER4uBEffjk2UF5JI6uCMqUORlVzLfXY=";

    private base64senderPublicKey = '04950C7C0BED23C3CAC5CC31BBB9AAD9BB5532387882670AC2B1CDF0799AB0EBC764C267F704E8FDDA0796AB8397A4D2101024D24C4EFFF695B3A417F2ED0E48CD'

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

    }

    /*
     *  - Since this token depends on identifier attestation, continue to open iframe to attestation.id who needs to provide the proof
     */
    getIdentifierAttestation() {
        // attach postMessage listener and wait for attestation data
        this.attachPostMessageListener(this.postMessageAttestationListener.bind(this));
        const iframe = document.createElement('iframe');
        this.iframe = iframe;
        iframe.src = this.attestationOrigin;
        iframe.style.width = '800px';
        iframe.style.height = '700px';
        iframe.style.maxWidth = '100%';
        iframe.style.background = '#fff';
        // iframe.onload = ()=>{
        //     iframe.contentWindow.postMessage({force: false}, this.attestationOrigin);
        // };
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

        console.log(event)

        if (
            typeof event.data.ready !== "undefined"
            && event.data.ready === true
        ) {
            this.iframe.contentWindow.postMessage({force: false}, this.attestationOrigin);
            return;
        }


        if (
            typeof event.data.display !== "undefined"
        ) {
            if (event.data.display === true) {
                this.iframeWrap.style.display = 'flex';
            } else {
                this.iframeWrap.style.display = 'none';
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
        // this.attestationBlob = "MIICdjCCAh2gAwIBEgIIQebpgDCvmAAwCQYHKoZIzj0CATAWMRQwEgYDVQQDDAtB" +
        //     "bHBoYVdhbGxldDAiGA8yMDIxMDIwMTAwNDcyMloYDzIwMjEwMjAxMDE0NzIyWjA1" +
        //     "MTMwMQYDVQQDDCoweDMyRDlCOTM2MEIyRDczODAyNjM5Q0E4QTYyQkE2OTU0NDAz" +
        //     "M0VFNEUwggEzMIHsBgcqhkjOPQIBMIHgAgEBMCwGByqGSM49AQECIQD/////////" +
        //     "///////////////////////////+///8LzBEBCAAAAAAAAAAAAAAAAAAAAAAAAAA" +
        //     "AAAAAAAAAAAAAAAAAAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcE" +
        //     "QQR5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmEg62ncmo8RlXaT7/A4R" +
        //     "CKj9F7RIpoVUGZxH0I/7ENS4AiEA/////////////////////rqu3OavSKA7v9Je" +
        //     "jNA2QUECAQEDQgAE11WeT70GQ3pxayB3MM0J9Jtwa0Lb7lm8DPEtKlucnuI207a/" +
        //     "wYq5lghXdlxjMbu+UkTGJoaEXJyT6woIzmGM6KNXMFUwUwYLKwYBBAGLOnN5ASgB" +
        //     "Af8EQQQVzCsl2M8EzynLS2XwnKJtm1T5djndo4Zp4cOpXG2drBSeXnKejcy3FGSj" +
        //     "QudLBNlmEpJ1taXIftk3vdSadzNnMAkGByqGSM49AgEDSAAwRQIhAPwCo6NyW0hB" +
        //     "kJ6v2XSj7gHgE7qmTycCTkf0Cry26pzzAiAb0WU67Nadw9PnqXAmwpsKERcx+E5e" +
        //     "v0VCDh4xheZDiQ==";
        this.attestationSecret = event.data.requestSecret;
        // this.attestationSecret = uint8ToBn(base64ToUint8array("MCIEICBw8j/S6Cs6t/NakecTLVSmHlzvqDIr5vqJbbOpTdq5"));

        // this.base64attestorPubKey = "MIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA////////////////" +
        //     "/////////////////////v///C8wRAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
        //     "AAAAAAAAAAAEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHBEEEeb5m" +
        //     "fvncu6xVoGKVzocLBwKb/NstzijZWfKBWxb4F5hIOtp3JqPEZV2k+/wOEQio/Re0" +
        //     "SKaFVBmcR9CP+xDUuAIhAP////////////////////66rtzmr0igO7/SXozQNkFB" +
        //     "AgEBA0IABL9fgFkHbEdmPJYyYSfMWBdtZWyRMDJ7YfKyP1ZwEAOJ9MKWKPZ/hGGF" +
        //     "bVpDpCkO8U+ymmF17ybMcyT4SJ8GTII=";

        console.log('attestation data received:');
        console.log(this.attestationBlob);
        console.log(this.attestationSecret);
        console.log(this.base64attestorPubKey);

        try {
            let useToken = main.getUseTicket(
                this.signedTokenSecret,
                this.attestationSecret,
                this.signedTokenBlob ,
                this.attestationBlob ,
                this.base64attestorPubKey,
                this.base64senderPublicKey,
            )
            this.authResultCallback(useToken);
        } catch (e){
            console.log(`UseDevconTicket. Something went wrong. ${e}`);
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



    /*
     * get ticket attestation from wallet, or issuer site's local storage through iframe
     *  - Open an Iframe and obtain the data object (in this case SignedDevonTicket)
     */
    // function

    // getTokenAttestation(tokenObj) {
    // }

}
