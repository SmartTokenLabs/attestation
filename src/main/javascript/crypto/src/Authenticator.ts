import {SignedDevconTicket} from "./asn1/shemas/SignedDevconTicket";
import {Ticket} from "./Ticket";
import {TicketDecoder} from "./TicketDecoder";
import {KeyPair} from "./libs/KeyPair";
import {base64ToUint8array, uint8ToBn, uint8tohex} from "./libs/utils";
import {SubjectPublicKeyInfo} from "./asn1/shemas/AttestationFramework";
import {AsnParser} from "@peculiar/asn1-schema";
import {SignedAttestation} from "./libs/SignedAttestation";
import {AttestedObject} from "./libs/AttestedObject";

declare global {
    interface Window {
        attachEvent: any;
        detachEvent: any;
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
    private base64senderPublicKey: string;
    private base64attestorPubKey: string;

    constructor(private negotiator: any = false) {
        let XMLconfig = {
            attestationOrigin: "http://stage.attestation.id",
            tokensOrigin: "https://devcontickets.herokuapp.com/outlet/",
            tokenUrlName: 'ticket',
            tokenSecretName: 'secret',
            unsignedTokenDataName: 'ticket',
            // tokenParserUrl: '',
            tokenParser: SignedDevconTicket,
            localStorageItemName: 'dcTokens',
            base64senderPublicKey: '04950C7C0BED23C3CAC5CC31BBB9AAD9BB5532387882670AC2B1CDF0799AB0EBC764C267F704E8FDDA0796AB8397A4D2101024D24C4EFFF695B3A417F2ED0E48CD',

            base64attestorPubKey:
                // stage.attestation.id public key
                "MIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA/////////////////////////////////////v///C8wRAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHBEEEeb5mfvncu6xVoGKVzocLBwKb/NstzijZWfKBWxb4F5hIOtp3JqPEZV2k+/wOEQio/Re0SKaFVBmcR9CP+xDUuAIhAP////////////////////66rtzmr0igO7/SXozQNkFBAgEBA0IABL+y43T1OJFScEep69/yTqpqnV/jzONz9Sp4TEHyAJ7IPN9+GHweCX1hT4OFxt152sBN3jJc1s0Ymzd8pNGZNoQ="
        };

        // this.negotiator = negotiator;

        this.base64senderPublicKey = XMLconfig.base64senderPublicKey;
        this.base64attestorPubKey = XMLconfig.base64attestorPubKey;
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
        this.signedTokenSecret = tokenObj.ticketSecret;
        this.attestationOrigin = tokenObj.attestationOrigin;
        this.authResultCallback = authResultCallback;
        // TODO temporary disable, while stage.attestaion.id broken
        this.getIdentifierAttestation();

    }

    /*
     *  - Since this token depends on identifier attestation, continue to open iframe to attestation.id who needs to provide the proof
     */
    getIdentifierAttestation() {
        console.log('getIdentifierAttestation. create iframe.')
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

    getUseTicket(
        // userKey: KeyPair,
        ticketSecret: bigint,
        attestationSecret: bigint,
        base64ticket: string,
        base64attestation: string,
        base64attestationPublicKey: string,
        base64senderPublicKey: string
    )
    {

        let ticket: Ticket = TicketDecoder.fromBase64(base64ticket, KeyPair.fromPublicHex(base64senderPublicKey));
        if (!ticket.checkValidity()) {
            console.log("Could not validate cheque");
            throw new Error("Validation failed");
        }
        if (!ticket.verify()) {
            console.log("Could not verify ticket");
            throw new Error("Verification failed");
        }
        console.log('ticked valid (signature OK)');

        let keyUint8data = base64ToUint8array(base64attestationPublicKey);
        let key:SubjectPublicKeyInfo = AsnParser.parse(keyUint8data, SubjectPublicKeyInfo);

        let attestorKey = KeyPair.fromPublicHex(uint8tohex(new Uint8Array(key.value.subjectPublicKey)));

        console.log('lets test attestaion:');
        let att = new SignedAttestation(base64attestation, attestorKey);

        if (!att.checkValidity()) {
            console.log("Could not validate attestation");
            throw new Error("Validation failed");
        }
        if (!att.verify()) {
            console.log("Could not verify attestation");
            throw new Error("Verification failed");
        }
        console.log('attestaion valid');

        let redeem: AttestedObject = new AttestedObject(
            ticket, att,
            BigInt(attestationSecret), BigInt(ticketSecret));

        // console.log("redeem.getDerEncodeProof(): ");
        // console.log(redeem.getDerEncodeProof());

        return redeem.getDerEncodeProof();

    }

    postMessageAttestationListener(event: MessageEvent){
        let attestURL = new URL(this.attestationOrigin);

        if (event.origin !== attestURL.origin) {
            return;
        }

        console.log('postMessageAttestationListener event');
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
                this.negotiator && this.negotiator.commandDisplayIframe();
            } else {
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

        console.log('attestation data received.');
        // console.log(this.attestationBlob);
        // console.log(this.attestationSecret);
        // console.log(this.base64attestorPubKey);

        try {
            let useToken = this.getUseTicket(
                this.signedTokenSecret,
                this.attestationSecret,
                this.signedTokenBlob ,
                this.attestationBlob ,
                this.base64attestorPubKey,
                this.base64senderPublicKey,
            )

            console.log('this.authResultCallback(useToken)');
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
