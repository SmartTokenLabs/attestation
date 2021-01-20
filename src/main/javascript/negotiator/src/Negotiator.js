import {SignedDevconTicket} from "./asn1/SignedDevonTicket.js";

export class Negotiator {
    // other code
    constructor(filter, options = {}) {
        this.filter = filter;
        this.debug = 0;
        this.hideTokensIframe = 0;
        this.attestationOrigin = "http://stage.attestation.id";
        this.tokensOrigin = "https://devcontickets.herokuapp.com/outlet/";
        if (options.hasOwnProperty('debug')) this.debug = options.debug;
        if (options.hasOwnProperty('attestationOrigin')) this.attestationOrigin = options.attestationOrigin;
        if (options.hasOwnProperty('tokensOrigin')) this.tokensOrigin = options.tokensOrigin;
    }

    /*
     * Return token objects satisfying the current negotiator's requirements
     */
    getTokenInstances() {
        let res = [];
        this.debug && console.log('filter:',this.filter);
        if (
            this.tokens.web.length
            && typeof this.filter === "object"
            && Object.keys(this.filter).length
        ) {
            let filterKeys = Object.keys(this.filter);
            this.tokens.web.forEach(token => {
                let fitFilter = 1;
                this.debug && console.log('test token:',token);
                filterKeys.forEach(key => {
                    if (token[key].toString() != this.filter[key].toString()) fitFilter = 0;
                })
                if (fitFilter) {
                    res.push(token);
                    this.debug && console.log('token fits:',token);
                }
            })
            return res;
        } else {
            return this.tokens.web;
        }
    }

    negotiate(callBack) {
        // its iframe, we will send tokens to parent
        if (window.addEventListener) {
            window.addEventListener("message", (e) => {
                this.parentPostMessagelistener(e,callBack);
            });
        } else {
            // IE8
            window.attachEvent("onmessage", (e) => {
                this.parentPostMessagelistener(e,callBack);
            });
        }

        const iframe = document.createElement('iframe');
        this.tokensIframe = iframe;
        // iframe.setAttribute('name', 'target');
        if (this.hideTokensIframe) {
            iframe.style.display = 'none';
        }
        const remoteUrl = this.tokensOrigin;
        iframe.src = remoteUrl;
        // iframe.onload = ()=>{
        //     // console.log("remoteUrl = " + remoteUrl);
        //     const url = new URL(remoteUrl);
        //     iframe.contentWindow.postMessage({get_tokens: "tickets"}, url.origin);
        // }
        document.body.appendChild(iframe);
    }

    base64ToUint8array( base64str ) {
        // decode base64url to base64. it will do nothing for base64
        base64str = base64str.split('_').join('+')
            .split('-').join('/')
            .split('.').join('=');
        let res;

        if (typeof Buffer !== 'undefined') {
            res = Uint8Array.from(Buffer.from(base64str, 'base64'));
        } else {
            res = Uint8Array.from(atob(base64str), c => c.charCodeAt(0));
        }
        return res;
    }

    decodeTokens(encodedTokens, callBack){
        if (this.debug) {
            console.log('decodeTokens fired');
            console.log(encodedTokens);
        }
        this.tokens = {raw: [], web: []};
        if (encodedTokens.length) {
            encodedTokens.forEach(token=> {
                let decodedToken = new SignedDevconTicket(this.base64ToUint8array(token.ticket).buffer);

                console.log('decodedToken = ', decodedToken);
                this.tokens.raw.push(token)
                if (decodedToken) this.tokens.web.push(decodedToken.ticket);
            })
            // this.filterTokens(callBack);
            callBack && callBack(this.getTokenInstances());
        }
    }


    // postMessageEvent
    parentPostMessagelistener(event, callBack ) {
        // console.log('post message received');
        // ignore system postMessages, we work with postMessages with defined event.data.tokens
        if (typeof event.data.tokens === "undefined") {
            return;
        }

        // console.log('tokens received');
        // console.log(event.data.tokens);

        if (this.debug) {
            console.log('---parent postMessage event received, event.data.tokens:', event.data.tokens);
        }

        // remove iframe when data received
        this.tokensIframe.remove();

        this.decodeTokens(JSON.parse(event.data.tokens), callBack);
    }
// it works in outlet
    /*
    static iframePostMessagelistener() {

        if (window === window.parent) {
            // its not a iframe. lets read tokens from url

            let negotiator = new Negotiator();
            negotiator.readTokens();
        }

        function listener(event) {
            this.debug = 0;

            if ("undefined" === typeof event.data.filter) {
                return;
            }
            const filter = event.data.filter;

            if (this.debug) {
                console.log('iframe postMessage event received:', filter);
            }

            const source = event.source;

            let negotiator = new Negotiator(filter);
            negotiator.negotiate((tokens) => {
                if (this.debug) {
                    console.log(tokens);
                }
                source.postMessage({tokens: tokens}, event.origin)
            })

        }
        if (window.addEventListener) {
            window.addEventListener("message", listener);
        } else {
            // IE8
            window.attachEvent("onmessage", listener);
        }
    }

     */

    // Get the token instances (with filter)
    /*
    readTokens() {

        // TODO open ticket.devcon.org and receive list of tickets
        // TODO filter tokens return

        // Get ticket from params - to add to local storage / read into app
        const urlParams = new URLSearchParams(window.location.search);
        const ticketFromQuery = urlParams.get('ticket');
        const secretFromQuery = urlParams.get('secret');
        // Get the current Storage Tokens (DER format)
        const storageTokens = localStorage.getItem('dcTokens');
        // Decode the current ticket (DER format)
        // root object { commitment, publicKeyInfo, signatureValue, ticket }
        // ticket example: "SignedDevconTicket{ticket: DevconTicket {devconId: 6n,ticketId: 417541561855n,ticketClass: 0n},commitment: ArrayBuffer {[Uint8Contents]: <04 12 35 64 9d 5b fd 29 fe c5 d8 5b 6d e9 05 4e dc 8d 36 79 16 9d 88 4d 64 27 a9 2f af dd f8 fd 30 29 38 b6 71 ae 1e 46 2f 78 cb a0 4c fd 26 fe 36 16 ca 4f bf f2 c7 15 ae 8c f4 06 8e b8 b0 2f 22>,byteLength: 65},publicKeyInfo: PublicKeyInfo { signatureAlgorithm: undefined, publicKey: undefined },signatureValue: ArrayBuffer {[Uint8Contents]: <30 44 02 20 70 2c af bd e4 d3 d9 a3 45 b4 d4 70 c1 7f 26 62 b1 9d 8a 68 da f3 a1 6b b1 45 5f e7 86 31 8b 30 02 20 68 e3 f8 79 55 48 34 7e 71 33 c0 af f4 e5 43 77 23 86 dc 1c 54 ab 23 d5 40 eb 83 53 d3 da 0b da>,byteLength: 70}}'";

        let ticketDecodedString;
        let ticketObject = {};

        if (ticketFromQuery) {
            ticketDecodedString = new SignedDevconTicket(ticketFromQuery);
            // Read from Decoded ticket String
            ticketObject = ticketDecodedString.ticket;
        }

        // Check if the ticket is valid (has data)
        const isValidTicket =
            ticketObject.ticketId && ticketObject.ticketClass && ticketObject.devconId;
        // Tickets for storage (raw) and for web view
        const tickets = {
            raw: [],
            web: []
        };
        // If Valid, return web friendly tickets
        if (isValidTicket) {
            // Check if its new or an existing ticket id:
            // If the ticket from the query is new / or to replace an existing ticket
            let isNewQueryTicket = true;
            if (storageTokens && storageTokens.length) {
                // Build new list of tickets from current and query ticket { ticket, secret }
                JSON.parse(storageTokens).map((tokenBlob) => {
                    // Decoded string to JS Object
                    const storedTicketObject = new SignedDevconTicket(tokenBlob.ticket);
                    // If the same as a previous ticket - replace with the new ticket
                    if (storedTicketObject.ticket.ticketId == ticketObject.ticketId) {
                        // If new push the DER of the ticket into localstorage
                        tickets.raw.push({ ticket: ticketFromQuery, secret: secretFromQuery });
                        // Push a js object
                        tickets.web.push(this.addWebTicket(ticketObject));
                        isNewQueryTicket = false;
                    } else {
                        // Else push the original DER - Check this is correct.
                        tickets.raw.push(tokenBlob); // contains the ticket and secret
                        tickets.web.push(this.addWebTicket(storedTicketObject));
                    }
                });
            }
            // Add ticket if new
            if (isNewQueryTicket) {
                tickets.raw.push({ ticket: ticketFromQuery, secret: secretFromQuery }); // new raw object
            }
            // Set New tokens list raw only, websters will be decoded each time
            localStorage.setItem('dcTokens', JSON.stringify(tickets.raw));
        } else { // no ticket in browser window, search for localstorage items
            if (storageTokens && storageTokens.length) {
                JSON.parse(storageTokens).map((tokenBlob) => {
                    // Decoded string to JS Object
                    const storedTicketObject = new SignedDevconTicket(tokenBlob.ticket);
                    // Push the original DER
                    tickets.raw.push(tokenBlob);
                    tickets.web.push(this.addWebTicket(storedTicketObject));
                });
            }
        }

        // Return tickets for web
        this.tokens = tickets;
        return tickets.web;
    }

    addWebTicket(ticketObj){
        // TODO move type correction to the webster
        return {
            devconId: ticketObj.ticket.devconId.toString(),
            ticketId: ticketObj.ticket.ticketId.toString(),
            ticketClass: ticketObj.ticket.ticketClass.toString()
        }
    }

    getTokenType(type) {
        // TODO use type
        return {
            attestationOrigin: this.attestationOrigin
        };
    }

     */
}
