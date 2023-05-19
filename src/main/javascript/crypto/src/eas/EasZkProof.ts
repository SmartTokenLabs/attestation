import {SignedIdentifierAttestation} from "../libs/SignedIdentifierAttestation";
import {base64ToUint8array, hexStringToBase64, logger} from "../libs/utils";
import {KeyPair, KeysArray, KeysConfig} from "../libs/KeyPair";
import {EASSignerOrProvider, EasTicketAttestation, TicketSchema} from "./EasTicketAttestation";
import {AttestedObject} from "../libs/AttestedObject";
import {UseToken} from "../asn1/shemas/UseToken";
import {DEBUGLEVEL} from "../config";

export class EasZkProof {

	constructor(private schema: TicketSchema,
				private EASconfig: {
					address: string // EAS resolver contract address
					version: string
					chainId: number
				},
				private provider: EASSignerOrProvider
	) {

	}

	public getUseTicket(
		ticketSecret: bigint,
		identifierSecret: bigint,
		base64TicketAttestation: string,
		base64IdentifierAttestation: string,
		attestorPublicKey: string,
		base64senderPublicKeys: KeysConfig|KeysArray
	){
		try {
			base64senderPublicKeys = KeyPair.parseKeyArrayStrings(base64senderPublicKeys);
		} catch(e){
			logger(DEBUGLEVEL.LOW, e);
			throw new Error("Issuer key error");
		}

		const idAttest = SignedIdentifierAttestation.fromBytes(base64ToUint8array(base64IdentifierAttestation), KeyPair.publicFromBase64orPEM(attestorPublicKey));
		const ticketAttest = new EasTicketAttestation(this.schema, this.EASconfig, this.provider);

		ticketAttest.loadFromEncoded(base64TicketAttestation, undefined,  <KeysArray>base64senderPublicKeys);

		let redeem: AttestedObject = new AttestedObject();
		redeem.create(ticketAttest, idAttest, identifierSecret, ticketSecret);

		let unSigned = redeem.getDerEncoding();

		return hexStringToBase64(unSigned);
	}

	public async validateUseTicket(proof:string, base64attestorPublicKey:string, base64issuerPublicKeys: {[key: string]: KeyPair|string}, userEthKey?: string){

		let attestorKey = KeyPair.publicFromBase64orPEM(base64attestorPublicKey);
		let issuerKeys = KeyPair.parseKeyArrayStrings(base64issuerPublicKeys);

		try {

			const self = this;

			const EasValidationWrapper = class extends EasTicketAttestation {
				constructor() {
					super(self.schema, self.EASconfig, self.provider);
				}
			}

			let decodedAttestedObject = AttestedObject.fromBytes(base64ToUint8array(proof), UseToken, attestorKey, EasValidationWrapper, issuerKeys);

			if (!decodedAttestedObject.checkValidity(userEthKey)){
				throw new Error("Ticket validity check failed!");
			}

			await (decodedAttestedObject.getAttestableObject() as EasTicketAttestation).validateEasAttestation()

			return decodedAttestedObject;

		} catch (e) {
			if (e instanceof Error) {
				let message = "Ticket proof validation failed! " + e.message;
				throw new Error(message);
			}
		}
	}
}