import { fromBER } from "asn1js";
import SignedTicket from "./ticket_schema/ticket_schema";

let asn1jsspan = document.querySelector("#asn1js");

export function updateAsn1jsSpan(text) {
  asn1jsspan.textContent = text;
}

const toBase64 = (file) => {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.readAsText(file, "UTF-8");
    // reader.readAsArrayBuffer(file);
    // reader.readAsDataURL(file);
    reader.onload = () => resolve(reader.result);
    reader.onerror = (error) => reject(error);
  });
};

export function decode(file) {
  const der = Buffer.from(file, "base64");

  const ber = new Uint8Array(der).buffer;

  const ans1 = fromBER(ber);

  const ticket = new SignedTicket({
    schema: ans1.result,
  });

  return ticket;
}

export async function decodeAnsn1(file) {
  const base64 = await toBase64(file);

  const result = decode(base64);
  return result;
}
