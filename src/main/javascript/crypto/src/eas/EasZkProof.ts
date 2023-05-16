import {SignedIdentifierAttestation} from "../libs/SignedIdentifierAttestation";
import {base64ToUint8array, hexStringToBase64} from "../libs/utils";
import {KeyPair, KeysArray} from "../libs/KeyPair";
import {EasTicketAttestation, TicketSchema} from "./EasTicketAttestation";
import {AttestedObject} from "../libs/AttestedObject";
import {ethers} from "ethers";
import {UseToken} from "../asn1/shemas/UseToken";

export class EasZkProof {

	constructor(private schema: TicketSchema,
				private EASconfig: {
					address: string // EAS resolver contract address
					version: string
					chainId: number
				},
				private provider: ethers.providers.Web3Provider
	) {

	}

	public create(
		base64TicketAttestation: string,
		ticketSecret: string,
		base64IdentifierAttestation: string,
		identifierSecret: string,
		attestorPublicKey: string,
		base64senderPublicKeys: KeysArray
	){

		const idAttest = SignedIdentifierAttestation.fromBytes(base64ToUint8array(base64IdentifierAttestation), KeyPair.publicFromBase64orPEM(attestorPublicKey));
		const ticketAttest = new EasTicketAttestation(this.schema, this.EASconfig, this.provider);
		ticketAttest.fromBytes(base64ToUint8array(base64TicketAttestation), base64senderPublicKeys);

		let redeem: AttestedObject = new AttestedObject();
		redeem.create(ticketAttest, idAttest, BigInt("0x" + identifierSecret), BigInt(ticketSecret));

		let unSigned = redeem.getDerEncoding();

		return hexStringToBase64(unSigned);
	}

	public async validateUseTicket(proof:string, base64attestorPublicKey:string, base64issuerPublicKeys: {[key: string]: KeyPair|string}, userEthKey: string){

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