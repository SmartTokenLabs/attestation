import {EasTicketAttestation, TicketSchema} from "./EasTicketAttestation";
import {EASIdentifierAttestation} from "./EASIdentifierAttestation";
import {AttestationCrypto} from "../libs/AttestationCrypto";
import {ProofOfExponentInterface} from "../libs/ProofOfExponentInterface";
import {hexStringToUint8, logger, uint8tohex} from "../libs/utils";
import {AsnParser, AsnProp, AsnPropTypes, AsnSerializer} from "@peculiar/asn1-schema";
import {KeyPair, KeysArray} from "../libs/KeyPair";
import {UsageProofOfExponent} from "../libs/UsageProofOfExponent";
import {DEBUGLEVEL} from "../config";

export class EasUseToken {

	@AsnProp({ type: AsnPropTypes.Any })
	public ticketAttestation: Uint8Array;

	@AsnProp({ type: AsnPropTypes.Any })
	public idAttestation: Uint8Array;

	@AsnProp({ type: AsnPropTypes.Any })
	public proof: Uint8Array;
}

export class EasAttestedObject {

	private crypto = new AttestationCrypto();

	private ticketAttestation: EasTicketAttestation;
	private ticketSecret: bigint;
	private identifierAttestation: EASIdentifierAttestation;
	private identifierSecret: bigint;

	private pok: ProofOfExponentInterface;

	create(
		ticketAttestation: EasTicketAttestation,
		ticketSecret: bigint,
		identifierAttestation: EASIdentifierAttestation,
		identifierSecret: bigint){

		this.ticketAttestation = ticketAttestation;
		this.ticketSecret = ticketSecret;
		this.identifierAttestation = identifierAttestation;
		this.identifierSecret = identifierSecret;

		this.pok = this.makeProof();
	}

	private makeProof(): ProofOfExponentInterface {

		let attCom: Uint8Array = this.identifierAttestation.getCommitment();
		let objCom: Uint8Array = this.ticketAttestation.getCommitment();
		let pok: ProofOfExponentInterface = this.crypto.computeEqualityProof(uint8tohex(attCom), uint8tohex(objCom), this.identifierSecret, this.ticketSecret);

		if (!this.crypto.verifyEqualityProof(attCom, objCom, pok)) {
			throw new Error("The redeem proof did not verify");
		}
		return pok;
	}

	getEncoded(){

		const useToken = new EasUseToken();
		useToken.ticketAttestation = new Uint8Array(this.ticketAttestation.getAsnEncoded());
		useToken.idAttestation = new Uint8Array(this.identifierAttestation.getAsnEncoded());
		useToken.proof = hexStringToUint8(this.pok.getDerEncoding());

		return uint8tohex(new Uint8Array(AsnSerializer.serialize(useToken)));
	}

	static fromBytes<T extends EasTicketAttestation, A extends EASIdentifierAttestation>(encoded: Uint8Array, ticketClass: new () => T, idClass: new () => A){

		const decoded = AsnParser.parse(encoded, EasUseToken);

		const me = new this();

		me.ticketAttestation = new ticketClass();
		me.ticketAttestation.loadAsnEncoded(decoded.ticketAttestation);

		me.identifierAttestation = new idClass();
		me.identifierAttestation.loadAsnEncoded(decoded.idAttestation);


		let pok = new UsageProofOfExponent();
		pok.fromBytes( new Uint8Array(decoded.proof) ) ;
		me.pok = pok;

		return me;
	}

	async checkValidity(ethAddress:string = ""){

		await this.ticketAttestation.validateEasAttestation();
		await this.identifierAttestation.validateEasAttestation();

		if (!this.crypto.verifyEqualityProof(
			this.identifierAttestation.getCommitment(),
			this.ticketAttestation.getCommitment(),
			this.pok
		)) {
			throw new Error("Could not verify the consistency between the commitment in the identifier and ticket attestations");
		}

		if (ethAddress !== ""){
			const attestedAddress = await this.identifierAttestation.getAttestationField("ethereumAddress");

			if (attestedAddress.toLowerCase() !== ethAddress.toLowerCase())
				throw Error("The provided ethereum address does not match the address specified in the identifier attestation");
		}

		return true;
	}
}