/*
 * Data Object classes: there should be one for each data module in
 * https://github.com/TokenScript/attestation/tree/main/data-modules/src
 * This is pseudo code for Bharat
 *
 */

class SignedDevconTicket {
    constructor(param) {
        if (param instanceof ArrayBuffer) {
            // parse ASN1 data encoded in DER
        } else if (typeof(param) == "string") {
            // parse ASN1 data encoded in CER
        } else {
            // shallow copy all attributes in the dictionary to this
        }
    }

    serialize() {
        // return DER encoded binary blo
    }
}

class UseDevonTicket {} // ditto
class Proof {} // ditto
class IdentifierAttestation {} // ditto

function testSignedDevconTicket(blob) {
    const dataobj = new SignedDevconTicket(blob);
    console.log(dataobj.ticket) // {devconID: 6, ticketID: 8900, ticketClass: "VIP"}
    console.log(dataobj.signatureAlgorithm) // "0.8.8.89.8093"
    console.log(dataobj.signatureValue) // "0x809830840280938409283409820483204329"
}

functoin testUseDevconTicket(devconTicket, identifierAttestation, proof) {
    const dataobj = new UseDeconTicket({
        signedDeconTicket: devconTicket, // a data object, see previous test
        attestation: identifierAttestation,
        proof: proof // proof is generated from Oleg's code
    });
    console.log(dataobj.serialize()); // something like this is used in mid-level Oleg code
}
