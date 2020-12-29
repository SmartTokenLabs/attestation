/*
 * TokenScript Negotiator/Authenticator pseudocode - Oleg's code
 */
class Negotiator {
    // other code

    /*
     * Return token objects satisfying the current negotiator's requirements
     */
    getTokenInstances() {
	// some code to get the signedDevconTicket from ticket.devcon.org (through iframe)
	    
        // the first 3 attributes are "Business Attributes", obtained from SignedDevonTicket.ticket
        // the last 3 attributes are "Operational Attributes"
        const ticket = {
            devconID: signedDevconTicket.ticket.devconID, // 6
            ticketID: signedDevconTicket.ticket.ticketId,
            ticketClass: signedDevconTicket.ticket.ticketClass, // "VIP"
            tokenClass: Symbol("DevconTicket"),
            ownerAddress: "0x147615dCEb7AAC2E7389037300b65e99B3b94F96",
            creationTimeStamp: new Date(2020, 1, 1, 0, 0, 0),
        }
         return [ticket]
    }
}

class Authenticator {

    getAuthenticationBlob(tokenObj) {
        // 1. Find the token type (using TokenScript)
        tokenType = Negotiator.getTokenType(tokenObj.tokenClass);

        // 2. Trace from its TokenScript which website has the needed data object
        if (tokenType.attestationOrigin) { // always return true in Devcon project,
            // unless DevCon changed their tokenscript and moved all tickets to the contract

            const signedDevonTicket = getTokenAttestation(tokenObj);
            const identifierAttestation = getIdentifierAttestation(tokenObj);
            const proof = generateIdentifierAttestationProof(identifierAttestation);
            // construct UseDevconTicket, see
            // https://github.com/TokenScript/attestation/blob/main/data-modules/src/UseDevconTicket.asd

            let useDevconTicket = new UseDevconTicket({
                signedDevconTicket: signedDevonTicket,
                identifierAttestation: identifierAttestation,
                proof: proof
            })
            // Serialise it (for use as a transaction parameter) and return it
            return useDevconTicket.serialize();
        }
    }

    /*
     * get ticket attestation from wallet, or issuer site's local storage through iframe
     *  - Open an Iframe and obtain the data object (in this case SignedDevonTicket)
     */
    function

    getTokenAttestation(tokenObj) {
    }

    /*
     *  - Since this token depends on identifier attestation, continue to open iframe to attestation.id who needs to provide the proof
     */
    function

    getIdentifierAttestation() {

    }

}
