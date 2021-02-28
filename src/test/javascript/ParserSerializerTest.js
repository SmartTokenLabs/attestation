
import { readFileSync, writeFileSync } from 'fs';

// testing SignedDevconTicket
import { SignedDevconTicket } from "../../main/javascript/SignedDevonTicket.js";
import {AttestationCrypto} from "../../main/javascript/crypto_js/lib/AttestationCrypto.js";
import {ATTESTATION_TYPE} from "../../main/javascript/crypto_js/lib/interfaces.js";


const der = readFileSync('build/test-results/signed-devcon-ticket.der');

/* who can tell me why not just do this?
const dataobj = new SignedDevconTicket(der.buffer);
 * the answer my friend, is blowing in the wind.
 * at least so the asn1.js library author Yury Strozhevsky thouht. His commen:
 * https://github.com/PeculiarVentures/ASN1.js/issues/58
 */
let dataobj1 =  new SignedDevconTicket(new Uint8Array(der).buffer);
console.log(dataobj1.toJSON());


// get PublicKeyInfo
const derpk = readFileSync('build/test-results/signed-devcon-ticket-with-pk.der');
let dataobj2 =  new SignedDevconTicket(new Uint8Array(derpk).buffer);
console.log(dataobj2.toJSON());


// get object from magiclink
const magiclink = readFileSync('build/test-results/mah@mah.com.url', 'utf8')
let dataobj3 = new SignedDevconTicket(magiclink);
console.log(dataobj3);


//get DER from object
let filePath="build/test-results/signed-devcon-ticket-new.der";
let finalDER;
finalDER = (new SignedDevconTicket(dataobj3)).serialize();
writeFileSync(filePath,  finalDER);
console.log("DER data is written to file"+filePath);

// Test if created file is correct
/*
const der1 = readFileSync('build/test-results/signed-devcon-ticket-new.der');
let dataobj2;
dataobj2 = new SignedDevconTicket(new Uint8Array(der1).buffer);
console.log(dataobj2);
*/


// instantiate by a dictionary object and ENCODE it

//let crypto = new AttestationCrypto();
//let commitment = crypto.makeCommitment('mah@mah.com', ATTESTATION_TYPE['mail'], BigInt(45845870611));

let dataobj4;
dataobj4 = new SignedDevconTicket({
    ticket: {
        devconId:Uint8Array.from('6').buffer,
        ticketId: Uint8Array.from('48646').buffer,
        ticketClass:Uint8Array.from('0').buffer
    },

    commitment: new Uint8Array([4, 65, 4, 32, 100, 48, -54, -30, 2, -27, -6, -76, 28, -27, 75, 116, 114, 94, 69, 79, -8, 8, 114, 10, 3, -112, 55, -40, 64, 61, -107, -2, -3, -64, 53, 18, 44, -107, -65, -46, -82, 26, 72, -93, -12, 47, 11, -114, 120, -5, 121, 35, 81, -83, -30, 10, 34, 9, -93, 31, 78, -112, -36, 97, -92, -43, 15]).buffer,

    signatureValue: new Uint8Array([48, 68, 2, 32, 56, -37, 33, -74, -75, -73, -58, -110, -38, -83, -94, -74, 46, -69, -119, -27, -93, 110, 58, 60, -50, 102, 30, 56, 83, 43, -55, -84, -56, 92, 52, 27, 2, 32, 112, 70, 115, 33, -113, 119, -78, 71, -75, 81, -85, 60, 61, 116, -31, -17, -113, 79, 126, 58, -32, 64, 29, 83, 84, 38, 101, 58, -86, 94, -62, -94]).buffer

});
let finalDER2 = dataobj4.serialize();
writeFileSync('build/test-results/signed-devcon-ticket-new-2.der',  finalDER2);


