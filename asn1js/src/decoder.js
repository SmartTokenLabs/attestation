import { fromBER } from "asn1js";
import SignedTicket from "./ticket_schema/ticket_schema";

let asn1jsspan = document.querySelector("#asn1js");

export function updateAsn1jsSpan(text) {
  asn1jsspan.textContent = text;
}

export function decode(inputContent) {
  const der = Buffer.from(inputContent, "base64");

  const ber = new Uint8Array(der).buffer;

  const ans1 = fromBER(ber);

  const ticket = new SignedTicket({
    schema: ans1.result,
  });

  return ticket;
}

export async function decodeAnsn1(input) {
  const inputContent = input.value;

  const result = decode(inputContent);
  return result;
}
