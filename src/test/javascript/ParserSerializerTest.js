
import { readFileSync } from 'fs';

console.log(typeof(blaster))


// testing SignedDevconTicket
import SignedDevconTicket from "../../main/javascript/SignedDevonTicket.js"
const der = readFileSync('build/test-results/signed-devcon-ticket.der')

/* who can tell me why not just do this?
const dataobj = new SignedDevconTicket(der.buffer);
 * the answer my friend, is blowing in the wind.
 * at least so the asn1.js library author Yury Strozhevsky thouht. His commen:
 * https://github.com/PeculiarVentures/ASN1.js/issues/58
 */
var dataobj = new SignedDevconTicket(new Uint8Array(der).buffer);


const { devconId, ticketClass, ticketId, riddle } = dataobj;
const text = `devconId = ${devconId}, ticketId = ${ticketId}, ticketClass = ${ticketClass}, riddle = ${riddle}`;


console.log(text);

// Go on and test every other Parser-Serializer


