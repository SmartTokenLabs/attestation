
import { readFileSync, writeFileSync } from 'fs';

// testing SignedDevconTicket
import { SignedDevconTicket } from "../../main/javascript/SignedDevonTicket.js"
const der = readFileSync('build/test-results/signed-devcon-ticket.der')

/* who can tell me why not just do this?
const dataobj = new SignedDevconTicket(der.buffer);
 * the answer my friend, is blowing in the wind.
 * at least so the asn1.js library author Yury Strozhevsky thouht. His commen:
 * https://github.com/PeculiarVentures/ASN1.js/issues/58
 */
let dataobj;

dataobj = new SignedDevconTicket(new Uint8Array(der).buffer);

console.log(dataobj);

//get DER from object
let bufferToFile;
bufferToFile = (new SignedDevconTicket(dataobj)).serialize();
writeFileSync('build/test-results/signed-devcon-ticket-new.der',  Buffer.from(bufferToFile));
console.log(bufferToFile);

// Test if created file is correct
/*
const der1 = readFileSync('build/test-results/signed-devcon-ticket-new.der');
let dataobj2;
dataobj2 = new SignedDevconTicket(new Uint8Array(der1).buffer);
console.log(dataobj2);
*/

// get object from magiclink
const magiclink = readFileSync('build/test-results/mah@mah.com.url', 'utf8')
dataobj = new SignedDevconTicket(magiclink);

console.log(dataobj);


