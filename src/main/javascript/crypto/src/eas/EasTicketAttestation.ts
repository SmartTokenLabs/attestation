import {
	EAS,
	ATTESTATION_TYPE,
	Offchain,
	SignedOffchainAttestation,
	TypedDataSigner, SchemaEncoder
} from "@ethereum-attestation-service/eas-sdk";
import {BigNumber, ethers, Signer} from "ethers";
import {AttestationCrypto} from "../libs/AttestationCrypto";
import {AsnParser, AsnProp, AsnPropTypes, AsnSerializer} from "@peculiar/asn1-schema";
import {defaultAbiCoder, joinSignature} from "ethers/lib/utils";
import {hexStringToUint8, uint8tohex} from "../libs/utils";
import {OffchainAttestationParams} from "@ethereum-attestation-service/eas-sdk/dist/offchain/offchain";
import {Attestable} from "../libs/Attestable";
import {AttestableObject} from "../libs/AttestableObject";
import {SignerOrProvider} from "@ethereum-attestation-service/eas-sdk/dist/transaction";
import {decodeBase64ZippedBase64, StaticSchemaInformation, zipAndEncodeToBase64} from "./AttestationUrl";

export enum AbiFieldTypes {
	bool = 'bool',
	uint8 = 'uint8',
	uint16 = 'uint16',
	uint32 = 'uint32',
	uint64 = 'uint64',
	uint128 = 'uint128',
	uint256 = 'uint256',
	address = 'address',
	string = 'string',
	bytes = 'bytes',
	bytes32 = 'bytes32'
}

export interface SchemaField {
	name: string,
	type: AbiFieldTypes|string,
	isCommitment?: boolean
}

export interface TicketSchema {
	fields: SchemaField[]
}

export class  EasAsnEmbeddedSchema {
	@AsnProp({ type: AsnPropTypes.OctetString })
	public easAttestation: Uint8Array
	@AsnProp({ type: AsnPropTypes.BitString })
	public signatureValue: Uint8Array;
}

export class EasTicketAttestation extends AttestableObject implements Attestable {

	private signedAttestation: SignedOffchainAttestation;
	private signerAddress: string;
	private decodedData?: {[fieldName: string]: any};
	private commitmentSecret?: bigint;
	private crypto = new AttestationCrypto();

	constructor(
		private schema: TicketSchema,
		private EASconfig: {
			address: string // EAS resolver contract address
			version: string
			chainId: number
		},
		private signer: SignerOrProvider
	) {
		super();
	}

	private getEasSchema(){
		return this.schema.fields.map((field) => {
			return field.type + " " + field.name
		}).join(", ");
	}

	private checkAttestationIsLoaded(){
		if (!this.signedAttestation)
			throw new Error("Signed attestation must be loaded to call this function");
	}

	/**
	 * Issue a new offchain attestation for the provided ID
	 * @param data
	 * @param validity
	 * @param commitmentValue The email address or other value to be used for the perdersen commitment
	 * @param commitmentType
	 */
	async createEasAttestation(data: {[key: string]: string|number}, validity?: {from: number, to: number}, commitmentType = 'mail'){

		if (!("_isSigner" in this.signer))
			throw new Error("Please provide a valid signer for this function.");

		this.signerAddress = await (this.signer as unknown as Signer).getAddress();

		if (!this.signerAddress)
			new Error("Failed to get signer address");

		const fieldData = this.schema.fields.map((field) => {

			if (!data[field.name])
				throw new Error("Value for field " + field.name + " was not provided");

			let value = data[field.name]

			if (field.isCommitment){
				if (!this.commitmentSecret)
					this.commitmentSecret = this.crypto.makeSecret();

				value = this.createCommitment(value as string, commitmentType, this.commitmentSecret);

				console.log("Commitment value: ", value);
			}

			return {
				name: field.name,
				value,
				type: field.type
			}
		})

		const offchain = new Offchain(this.EASconfig);

		const schemaEncoder = new SchemaEncoder(this.getEasSchema());
		const encodedData = schemaEncoder.encodeData(fieldData);

		const newAttestation = await offchain.signOffchainAttestation({
			recipient: '0x0000000000000000000000000000000000000000',
			// Unix timestamp of when attestation expires. (0 for no expiration)
			expirationTime: validity?.to ?? 0,
			// Unix timestamp of current time
			time: validity?.from ?? Math.round(Date.now() / 1000),
			nonce: 0,
			/*schema: "0x4677bc98bd107f75d03d13cf41e158e38f1b826502dd31f87bf384c1a888cbdc",*/
			schema:   "0x0000000000000000000000000000000000000000000000000000000000000000",
			revocable: true,
			refUID: "0x0000000000000000000000000000000000000000000000000000000000000000",
			data: encodedData,
		}, this.signer as unknown as TypedDataSigner);

		console.log("attestation: ", newAttestation);

		const valid = offchain.verifyOffchainAttestationSignature(this.signerAddress, newAttestation)

		if (!valid)
			throw new Error("Attestation signature check failed!");

		this.signedAttestation = newAttestation;

		return this.getEasJson();
	}

	private createCommitment(commitmentValue: string, commitmentType: string, commitmentSecret: bigint){
		return "0x" + uint8tohex(this.crypto.makeCommitment(commitmentValue, this.crypto.getType(commitmentType), commitmentSecret))
	}

	getUrlEncoded(){
		return
	}

	getEasJson(){
		this.checkAttestationIsLoaded();

		const data: {sig: SignedOffchainAttestation, signer: string, secret?: string} =  {
			sig: this.signedAttestation,
			signer: this.signerAddress,
		};

		if (this.commitmentSecret)
			data.secret = "0x" + this.commitmentSecret.toString(16)

		return data;
	}

	getEasUid(message?: OffchainAttestationParams){

		if (!message)
			this.checkAttestationIsLoaded();

		return Offchain.getOffchainUID(message ?? this.signedAttestation.message)
	}

	getEncoded(lightweight = false){
		return zipAndEncodeToBase64(this.getEasJson(), lightweight);
	}

	// TODO: Return ID based on decoded data
	/*getTicketId(){
		this.checkAttestationIsLoaded();
	}*/

	getAttestationData(){
		this.checkAttestationIsLoaded();

		if (!this.decodedData) {
			const schemaEncoder = new SchemaEncoder(this.getEasSchema());

			const dataArr = schemaEncoder.decodeData(this.signedAttestation.message.data);

			this.decodedData = {};

			let index = 0

			for (const value of this.schema.fields){
				this.decodedData[value.name] = dataArr[index].value;
				index++;
			}

			//this.decodedData["commitment"] = dataArr[index].value;
		}

		return this.decodedData;
	}

	getAttestationField(fieldName: string){

		const data = this.getAttestationData();

		if (!data[fieldName])
			throw new Error("The attestation does not contain data field '" + fieldName + "'");

		return data[fieldName]
	}

	verifyIdCommitment(commitValue: string, commitSecret?: bigint, commitmentType = 'mail'){

		if (commitSecret)
			this.commitmentSecret = commitSecret;

		if (!this.commitmentSecret)
			throw new Error("Commitment secret required.");

		const calced = this.createCommitment(commitValue, commitmentType, this.commitmentSecret);

		const commit = this.getAttestationField("commitment").value;

		console.log("calced", calced);
		console.log("commit", commit);

		if (calced !== commit)
			throw new Error("Commitment verification failed.");
	}

	async validateEasAttestation(){

		this.checkAttestationIsLoaded();

		// Signature check
		this.verify();

		// Expiry check
		this.checkValidity();

		await this.checkRevocation()
	}

	private async checkRevocation(uid?: string){

		if (!uid)
			uid = this.getEasUid();

		const eas = new EAS(this.EASconfig.address, {signerOrProvider: this.signer});

		const revoked = await eas.getRevocationOffchain(this.signerAddress, uid);

		console.log("getRevocationOffchain Revoked: ", revoked);

		if (BigNumber.from(revoked).gt(0)) {
			const msg = "Attestation has been revoked :-(";
			//alert(msg);
			throw new Error(msg);
		}
	}

	async revokeEasAttestation(uid?: string){

		if (!uid)
			uid = this.getEasUid();

		if (!("_isSigner" in this.signer))
			throw new Error("Please provide a valid signer");

		const eas = new EAS(this.EASconfig.address, {signerOrProvider: this.signer});

		const tx = await eas.revokeOffchain(uid);

		await tx.wait();
	}

	async bulkRevokeEasAttestations(uids: string[]){

		if (!("_isSigner" in this.signer))
			throw new Error("Please provide a valid signer");

		const eas = new EAS(this.EASconfig.address, {signerOrProvider: this.signer});

		const tx = await eas.multiRevokeOffchain(uids);

		await tx.wait();
	}

	loadEasAttestation(attestation: SignedOffchainAttestation, signerAddress: string, commitmentSecret?: string){
		this.decodedData = undefined;
		this.commitmentSecret = commitmentSecret ? BigInt(commitmentSecret) : undefined;
		this.signedAttestation = attestation;
		this.signerAddress = signerAddress;
	}

	loadFromEncoded(base64: string, schemaInfo: StaticSchemaInformation, commitmentSecret?: string){
		const decoded = decodeBase64ZippedBase64(base64, schemaInfo);

		this.loadEasAttestation(decoded.sig as SignedOffchainAttestation, decoded.signer, commitmentSecret)
	}

	getAsnEncoded(){

		const abiEncoded = defaultAbiCoder.encode(
			this.signedAttestation.types.Attest.map((field) => field.type),
			this.signedAttestation.types.Attest.map((field) => this.signedAttestation.message[field.name])
		);

		console.log("ABI Encoded bytes: ", abiEncoded);

		const asnEmbedded = new EasAsnEmbeddedSchema();
		asnEmbedded.easAttestation = hexStringToUint8(abiEncoded);
		asnEmbedded.signatureValue = hexStringToUint8(joinSignature(this.signedAttestation.signature));

		return AsnSerializer.serialize(asnEmbedded);
	}

	loadAsnEncoded(bytes: ArrayBuffer|Uint8Array){

		this.decodedData = undefined;
		this.commitmentSecret = undefined;

		// console.log("Encoded ASN: ", ethers.utils.hexlify(new Uint8Array(bytes)));

		const asnEmbedded = AsnParser.parse(bytes, EasAsnEmbeddedSchema);

		// console.log("Decoded ASN", asnEmbedded);

		const offchain = new Offchain(this.EASconfig);

		// console.log("ABI Encoded bytes: ", "0x" + uint8tohex(new Uint8Array(asnEmbedded.easAttestation)));

		const abiDecoded = defaultAbiCoder.decode(ATTESTATION_TYPE.map((field) => field.type), "0x" + uint8tohex(new Uint8Array(asnEmbedded.easAttestation)));

		// console.log("Abi decoded: ", abiDecoded);

		const mappedDecodedValues = {};

		for (const [index, value] of ATTESTATION_TYPE.entries()){
			mappedDecodedValues[value.name] = abiDecoded[index];
		}

		const splitSignature = ethers.utils.splitSignature(new Uint8Array(asnEmbedded.signatureValue));

		// create hash from decoded data and recover signature to simulate embedding attestation in ASN.1
		const hash = ethers.utils._TypedDataEncoder.hash(offchain.getDomainTypedData(), {Attest: ATTESTATION_TYPE}, mappedDecodedValues);

		// console.log("Data hash: " + hash);

		const recAddr = ethers.utils.recoverAddress(hash, splitSignature);

		// console.log("Recovered address: " + recAddr);

		this.signerAddress = recAddr;

		this.signedAttestation = {
			domain: offchain.getDomainTypedData(),
			message: mappedDecodedValues as OffchainAttestationParams,
			types: {Attest: ATTESTATION_TYPE},
			primaryType: "Attestation",
			signature: {
				r: splitSignature.r,
				s: splitSignature.s,
				v: splitSignature.v,
			},
			uid: this.getEasUid(mappedDecodedValues as OffchainAttestationParams),
		};
	}

	checkValidity(): boolean {

		const now = Math.round(Date.now() / 1000);

		if (now < this.signedAttestation.message.time)
			throw new Error("Attestation not yet valid.");

		if (this.signedAttestation.message.expirationTime > 0 && now > this.signedAttestation.message.expirationTime)
			throw new Error("Attestation has expired.");

		return true;
	}

	verify(): boolean {

		const offchain = new Offchain(this.EASconfig);

		const valid = offchain.verifyOffchainAttestationSignature(this.signerAddress, this.signedAttestation);

		if (!valid) {
			const msg = "Attestation signature is invalid :-(";
			//alert(msg);
			throw new Error(msg);
		}

		// TODO: validate against sender public keys

		return true;
	}

	getCommitment(): Uint8Array {
		return hexStringToUint8(this.getAttestationField("commitment").value);
	}

	getDerEncoding(): string {
		return uint8tohex(new Uint8Array(this.getAsnEncoded()));
	}

	protected commitment: Uint8Array;
	protected encoded: string;

	fromBytes(bytes:  ArrayBuffer|Uint8Array){
		this.loadAsnEncoded(bytes);

		// TODO: Sender public keys
	}

}