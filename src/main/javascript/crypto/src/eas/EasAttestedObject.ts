import {EasTicketAttestation, TicketSchema} from "./EasTicketAttestation";
import {EASIdentifierAttestation} from "./EASIdentifierAttestation";
import {AttestationCrypto} from "../libs/AttestationCrypto";
import {ProofOfExponentInterface} from "../libs/ProofOfExponentInterface";
import {hexStringToUint8, logger, uint8tohex} from "../libs/utils";
import {AsnParser, AsnProp, AsnPropTypes, AsnSerializer} from "@peculiar/asn1-schema";
import {UsageProofOfExponent} from "../libs/UsageProofOfExponent";
import {defaultAbiCoder} from "ethers/lib/utils";

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

	getEncoded(format: "abi"|"asn" = "abi"){

		if (format === "abi"){

			return defaultAbiCoder.encode(
				["bytes", "bytes", "bytes"],
				[
					this.ticketAttestation.getAbiEncoded(),
					this.identifierAttestation.getAbiEncoded(),
					this.pok.getAbiEncoding()
				]
			)

		} else {

			const useToken = new EasUseToken();
			useToken.ticketAttestation = new Uint8Array(this.ticketAttestation.getAsnEncoded());
			useToken.idAttestation = new Uint8Array(this.identifierAttestation.getAsnEncoded());
			useToken.proof = hexStringToUint8(this.pok.getDerEncoding());

			return uint8tohex(new Uint8Array(AsnSerializer.serialize(useToken)));
		}
	}

	static fromBytes<T extends EasTicketAttestation, A extends EASIdentifierAttestation>(encoded: Uint8Array, ticketClass: new () => T, idClass: new () => A, format: "abi"|"asn" = "abi"){

		const me = new this();
		me.ticketAttestation = new ticketClass();
		me.identifierAttestation = new idClass();

		let parts: {
			ticketAttestation: Uint8Array,
			idAttestation: Uint8Array
			proof: Uint8Array
		}

		let pok = new UsageProofOfExponent();

		if (format === "abi"){

			const decoded = defaultAbiCoder.decode(
				["bytes", "bytes", "bytes"],
				encoded
			);

			parts = {
				ticketAttestation: hexStringToUint8(decoded[0]),
				idAttestation: hexStringToUint8(decoded[1]),
				proof: hexStringToUint8(decoded[2])
			}

			pok.fromAbiBytes(parts.proof);

		} else {
			parts = AsnParser.parse(encoded, EasUseToken);
			pok.fromBytes(new Uint8Array(parts.proof));
		}

		me.ticketAttestation.loadBinaryEncoded(format, parts.ticketAttestation);
		me.identifierAttestation.loadBinaryEncoded(format, parts.idAttestation);
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