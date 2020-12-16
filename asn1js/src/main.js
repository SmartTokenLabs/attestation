import { decodeAnsn1, updateAsn1jsSpan } from "./decoder";

const fileInput = document.getElementById("asn1js-coded-input");

const handleFiles = async () => {
  const selectedFile = fileInput.files[0];

  //   const base64 = await toBase64(selectedFile);
  //   const result = decode(base64);
  const { ticketClass, ticketId, conferenceId } = await decodeAnsn1(
    selectedFile
  );

  const text = `ticketId = ${ticketId}, ticketClass = ${ticketClass}, conferenceId = ${conferenceId}`;

  updateAsn1jsSpan(text);
};

fileInput.addEventListener("change", handleFiles);
