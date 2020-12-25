import { decodeAnsn1, updateAsn1jsSpan } from "./decoder";

const input = document.getElementById("asn1js-coded-input");

const handleFiles = async () => {

  //   const base64 = await toBase64(selectedFile);
  //   const result = decode(base64);
  const { ticketClass, ticketId, conferenceId, riddle } = await decodeAnsn1(input);

  const text = `ticketId = ${ticketId}, ticketClass = ${ticketClass}, conferenceId = ${conferenceId}, riddle = ${riddle}`;

  updateAsn1jsSpan(text);
};

input.addEventListener("change", handleFiles);
