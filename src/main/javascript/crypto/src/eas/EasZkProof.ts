import {SignedIdentifierAttestation} from "../libs/SignedIdentifierAttestation";
import {base64ToUint8array, hexStringToBase64, logger} from "../libs/utils";
import {KeyPair, KeysArray, KeysConfig} from "../libs/KeyPair";
import {EasTicketAttestation, TicketSchema} from "./EasTicketAttestation";
import {AttestedObject} from "../libs/AttestedObject";
import {UseToken} from "../asn1/shemas/UseToken";
import {DEBUGLEVEL} from "../config";
import {EASIdentifierAttestation} from "./EASIdentifierAttestation";
import {EasAttestedObject} from "./EasAttestedObject";

export class EasZkProof {

	constructor(
		private schema: TicketSchema,
		private rpcMap: {[chainId: number]: string}
	) {

	}

	public getUseTicket(
		ticketSecret: bigint,
		identifierSecret: bigint,
		base64TicketAttestation: string,
		base64IdentifierAttestation: string,
		attestorPublicKey: string,
		base64senderPublicKeys: KeysConfig|KeysArray,
		identifierFormat?: "asn"|"eas",
		outputFormat: "abi"|"asn" = "abi"
	){
		try {
			base64senderPublicKeys = KeyPair.parseKeyArrayStrings(base64senderPublicKeys);
		} catch(e){
			logger(DEBUGLEVEL.LOW, e);
			throw new Error("Issuer key error");
		}

		const ticketAttest = new EasTicketAttestation(this.schema, undefined, this.rpcMap);

		ticketAttest.loadFromEncoded(base64TicketAttestation, <KeysArray>base64senderPublicKeys);

		let encodedUseTicket;

		if (identifierFormat === "eas"){

			const idAttest = (new EASIdentifierAttestation(undefined, KeyPair.publicFromBase64orPEM(attestorPublicKey)));
			idAttest.loadFromEncoded(base64IdentifierAttestation)

			const redeem = new EasAttestedObject();
			redeem.create(ticketAttest, ticketSecret, idAttest, identifierSecret);

			encodedUseTicket = redeem.getEncoded(outputFormat);

		} else {
			const idAttest = SignedIdentifierAttestation.fromBytes(base64ToUint8array(base64IdentifierAttestation), KeyPair.publicFromBase64orPEM(attestorPublicKey));

			let redeem: AttestedObject = new AttestedObject();
			redeem.create(ticketAttest, idAttest, identifierSecret, ticketSecret);

			encodedUseTicket = redeem.getDerEncoding();
		}

		return hexStringToBase64(encodedUseTicket);
	}

	public async validateUseTicket(
		proof:string,
		base64attestorPublicKey:string,
		base64issuerPublicKeys: {[key: string]: KeyPair|string},
		userEthKey?: string,
		identifierFormat?: "asn"|"eas",
		outputFormat: "abi"|"asn" = "abi"
	){

		let attestorKey = KeyPair.publicFromBase64orPEM(base64attestorPublicKey);
		let issuerKeys = KeyPair.parseKeyArrayStrings(base64issuerPublicKeys);

		const self = this;

		const EasTicketWrapper = class extends EasTicketAttestation {
			constructor() {
				super(self.schema, undefined, self.rpcMap, issuerKeys);
			}
		}

		if (identifierFormat === "eas"){

			const EasIdWrapper = class extends EASIdentifierAttestation {
				constructor() {
					super(undefined, attestorKey);
				}
			}

			const decodedAttestedObject = EasAttestedObject.fromBytes(base64ToUint8array(proof), EasTicketWrapper, EasIdWrapper, outputFormat);
			await decodedAttestedObject.checkValidity(userEthKey);

		} else {

			const decodedAttestedObject = AttestedObject.fromBytes(base64ToUint8array(proof), UseToken, attestorKey, EasTicketWrapper, issuerKeys);

			if (!decodedAttestedObject.checkValidity(userEthKey)){
				throw new Error("Ticket validity check failed!");
			}

			await (decodedAttestedObject.getAttestableObject() as EasTicketAttestation).validateEasAttestation();

			return decodedAttestedObject;
		}
	}
}