import {SignedDevconTicket} from "../../SignedDevconTicket";

export class Negotiator {
    // other code
    constructor(filter = {}, options = {}) {
        let XMLconfig = {
            attestationOrigin: "http://stage.attestation.id",
            tokensOrigin: "https://devcontickets.herokuapp.com/outlet/",
            tokenUrlName: 'ticket',
            tokenSecretName: 'secret',
            unsignedTokenDataName: 'ticket',
            // tokenParserUrl: '',
            tokenParser: SignedDevconTicket,
            localStorageItemName: 'dcTokens'
        };
        this.filter = filter;
        this.debug = 0;
        this.hideTokensIframe = 1;
        this.tokensOrigin = XMLconfig.tokensOrigin;
        this.attestationOrigin = XMLconfig.attestationOrigin;
        this.tokenUrlName = XMLconfig.tokenUrlName;
        this.tokenSecretName = XMLconfig.tokenSecretName;
        this.unsignedTokenDataName = XMLconfig.unsignedTokenDataName;
        this.tokenParser = XMLconfig.tokenParser;
        this.localStorageItemName = XMLconfig.localStorageItemName;

        if (options.hasOwnProperty('debug')) this.debug = options.debug;
        if (options.hasOwnProperty('attestationOrigin')) this.attestationOrigin = options.attestationOrigin;
        if (options.hasOwnProperty('tokensOrigin')) this.tokensOrigin = options.tokensOrigin;

        this.isTokenOriginWebsite = false;

        if (this.attestationOrigin) {
            // if attestationOrigin filled then token need attestaion
            let currentURL = new URL(window.location.href);
            let tokensOriginURL = new URL(this.tokensOrigin);

            if (currentURL.origin === tokensOriginURL.origin) {
                // its tokens website, where tokens saved in localStorage
                // lets chech url params and save token data to the local storage
                this.isTokenOriginWebsite = true;
                this.readMagicUrl();
            }
        }

        if (window !== window.parent){
            this.debug && console.log('negotiator: its iframe, lets return tokens to the parent');
            // its iframe, just return all tokens by config
            this.returnTokensToParent();
        }
    }

    returnTokensToParent(){
        let tokensOutput = this.readTokens();
        if (tokensOutput.success && !tokensOutput.noTokens) {
            let decodedTokens = this.decodeTokens(tokensOutput.tokens);
            let filteredTokens = this.filterTokens(decodedTokens);
            tokensOutput.tokens = filteredTokens;
        }
        let referrer = new URL(document.referrer);
        window.parent.postMessage({tokensOutput}, referrer.origin);
    }

    readMagicUrl() {
        const urlParams = new URLSearchParams(window.location.search);
        const tokenFromQuery = urlParams.get(this.tokenUrlName);
        const secretFromQuery = urlParams.get(this.tokenSecretName);

        if (! (tokenFromQuery && secretFromQuery) ) {
            return;
        }

        // Get the current Storage Tokens
        let tokensOutput = this.readTokens();
        let tokens = [];

        let isNewQueryTicket = true;

        if (!tokensOutput.noTokens) {
            // Build new list of tickets from current and query ticket { ticket, secret }
            tokens = tokensOutput.tokens;
            if (!tokenFromQuery || !secretFromQuery){
                tokens.map(tokenData => {
                    if (tokenData.token === tokenFromQuery) {
                        isNewQueryTicket = false;
                    }
                });
            }
        }

        // Add ticket if new
        // if (isNewQueryTicket && tokenFromQuery && secretFromQuery) {
        if (isNewQueryTicket) {
            tokens.push({token: tokenFromQuery, secret: secretFromQuery}); // new raw object
        }
        // Set New tokens list raw only, websters will be decoded each time
        localStorage.setItem(this.localStorageItemName, JSON.stringify(tokens));
    }

    /*
     * Return token objects satisfying the current negotiator's requirements
     */
    filterTokens(decodedTokens) {
        let res = [];
        if (
            decodedTokens.length
            && typeof this.filter === "object"
            && Object.keys(this.filter).length
        ) {
            let filterKeys = Object.keys(this.filter);
            decodedTokens.forEach(token => {
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
            return decodedTokens;
        }
    }

    // read tokens from local storage and return as object {tokens: [], noTokens: boolean, success: boolean}
    readTokens(){
        const storageTickets = localStorage.getItem(this.localStorageItemName);
        let tokens = [];
        let output = {tokens: [], noTokens: true, success: true};
        try {
            if (storageTickets && storageTickets.length) {
                // Build new list of tickets from current and query ticket { ticket, secret }
                tokens = JSON.parse(storageTickets);
                if (tokens.length !== 0) {
                    output.noTokens = false;
                    output.tokens = tokens;
                }
            }
        } catch (e) {
            console.log('Cant parse tokens in LocalStorage');
            if (typeof callBack === "function") {
                output.success = false;
            }
        }
        return output;
    }


    negotiate(callBack) {
        // callback function required
        if (typeof callBack !== "function") {
            return false;
        }

        this.negotiateCallback = callBack;

        if (this.attestationOrigin) {
            if (this.isTokenOriginWebsite) {
                let tokensOutput = this.readTokens();
                if (tokensOutput.success && !tokensOutput.noTokens) {
                    let decodedTokens = this.decodeTokens(tokensOutput.tokens);
                    let filteredTokens = this.filterTokens(decodedTokens);
                    tokensOutput.tokens = filteredTokens;
                    this.negotiateCallback(tokensOutput);
                }
            } else {
                // open iframe and request tokens
                let tokensOriginURL = new URL(this.tokensOrigin);
                this.attachPostMessageListener(event => {

                    if (event.origin !== tokensOriginURL.origin) {
                        return;
                    }

                    if (typeof event.data.tokensOutput === "undefined") {
                        return;
                    }
                    let tokensOutput = event.data.tokensOutput;
                    this.tokensIframe.remove();

                    if (tokensOutput.success && !tokensOutput.noTokens) {
                        let filteredTokens = this.filterTokens(tokensOutput.tokens);
                        tokensOutput.tokens = filteredTokens;
                    }
                    this.negotiateCallback(tokensOutput);

                });

                const iframe = document.createElement('iframe');
                this.tokensIframe = iframe;
                if (this.hideTokensIframe) {
                    iframe.style.display = 'none';
                }
                iframe.src = this.tokensOrigin;
                document.body.appendChild(iframe);
            }
        } else {
            console.log('no attestationOrigin...');
            // TODO test token against blockchain and show tokens as usual view
        }
    }

    base64ToUint8array( base64str ) {
        // decode base64url to base64. it will do nothing for base64
        base64str = base64str.split('-').join('+')
            .split('_').join('/')
            .split('.').join('=');
        let res;

        if (typeof Buffer !== 'undefined') {
            res = Uint8Array.from(Buffer.from(base64str, 'base64'));
        } else {
            res = Uint8Array.from(atob(base64str), c => c.charCodeAt(0));
        }
        return res;
    }

    decodeTokens(rawTokens){
        if (this.debug) {
            console.log('decodeTokens fired');
            console.log(rawTokens);
        }
        let decodedTokens = [];
        if (rawTokens.length) {
            rawTokens.forEach(tokenData=> {
                let decodedToken = new this.tokenParser(this.base64ToUint8array(tokenData.token).buffer);
                if (decodedToken && decodedToken[this.unsignedTokenDataName]) decodedTokens.push(decodedToken[this.unsignedTokenDataName]);
            })
        }
        return decodedTokens;
    }

    attachPostMessageListener(listener){
        if (window.addEventListener) {
            window.addEventListener("message", e =>
                listener(e), false);
        } else {
            // IE8
            window.attachEvent("onmessage", (e) => {
                listener(e);
            });
        }
    }
}
