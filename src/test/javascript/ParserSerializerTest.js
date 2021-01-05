
import { readFileSync } from 'fs';

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

const magiclink = readFileSync('build/test-results/mah@mah.com.url', 'utf8')
dataobj = new SignedDevconTicket(magiclink);

console.log(dataobj);


