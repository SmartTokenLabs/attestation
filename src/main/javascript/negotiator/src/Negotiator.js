import {SignedDevconTicket} from "../../SignedDevonTicket";

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
        if (this.hideTokensIframe) {
            iframe.style.display = 'none';
        }
        const remoteUrl = this.tokensOrigin;
        iframe.src = remoteUrl;
        // we can enable it if we need to send request to iframe on load
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
        // ignore system postMessages, we work with postMessages with defined event.data.tokens
        if (typeof event.data.tokens === "undefined") {
            return;
        }

        if (this.debug) {
            console.log('---parent postMessage event received, event.data.tokens:', event.data.tokens);
        }

        // remove iframe when data received
        this.tokensIframe.remove();

        this.decodeTokens(JSON.parse(event.data.tokens), callBack);
    }
}
