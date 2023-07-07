import {EasTicketAttestation, EasTicketCreationOptions} from "./EasTicketAttestation";
import {Signer} from "ethers";
import {KeyPair, KeysArray} from "../libs/KeyPair";

export interface EasIdentiferParameters {
	version: number;
	identifierType: "email";
	commitment: string;
	ethereumAddress: string;
}

export class EASIdentifierAttestation extends EasTicketAttestation {

	constructor(
		signingConfig?: {
			EASconfig: {
				address: string // EAS resolver contract address
				version: string
				chainId: number
			},
			signer: Signer
		},
		issuerKey?: KeyPair|string
	) {
		const schema = {
			fields: [
				{name: "version", type: "uint8"},
				{name: "identifierType", type: "string"},
				{name: "commitment", type: "bytes", isCommitment: true},
				{name: "ethereumAddress", type: "address"}
			]
		};

		super(schema, signingConfig, undefined, issuerKey ? <KeysArray>{"": issuerKey} : undefined);
	}

	async createEasAttestation(data: EasIdentiferParameters|any, options?: EasTicketCreationOptions, commitmentType = 'mail'){

		if (!options)
			options = {};

		// Identifier attestation is not revocable at this stage.
		if (options.revocable === undefined)
			options.revocable = false;

		if (!options.validity){
			const date = new Date();
			date.setDate(date.getDate() + 30);
			options.validity = {from: Math.round(Date.now() / 1000), to: Math.round(date.getTime() / 1000)}
		}

		return super.createEasAttestation(data, options, commitmentType);
	}
}