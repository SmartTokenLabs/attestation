
// TODO: Use this in KeyPair.ts too.
let subtle: SubtleCrypto;

if (typeof crypto === "object" && crypto.subtle){
	subtle = crypto.subtle;
} else {
	let webcrypto = require('crypto').webcrypto;
	if (webcrypto) {
		subtle = webcrypto.subtle;
	} else  {
		throw new Error("webcrypto.subtle missing");
	}
}

export default subtle;