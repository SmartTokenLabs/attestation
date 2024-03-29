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
import {base64UrltoBase64, base64toBase64Url, hexStringToUint8, uint8tohex} from "../libs/utils";
import {OffchainAttestationParams} from "@ethereum-attestation-service/eas-sdk/dist/offchain/offchain";
import {Attestable} from "../libs/Attestable";
import {AttestableObject} from "../libs/AttestableObject";
import {decodeBase64ZippedBase64, zipAndEncodeToBase64} from "./AttestationUrl";
import {KeyPair, KeysArray} from "../libs/KeyPair";
import {EIP712DomainTypedData} from "@ethereum-attestation-service/eas-sdk/dist/offchain/typed-data-handler";
import * as pako from "pako";

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

export interface EasTicketCreationOptions {
	recipient?: string,
	schema?: string,
	refUID?: string,
	validity?: {from: number, to: number}
}

export class  EasAsnEmbeddedSchema {
	@AsnProp({ type: AsnPropTypes.OctetString })
	public easAttestation: Uint8Array
	@AsnProp({ type: AsnPropTypes.BitString })
	public signatureValue: Uint8Array;
	@AsnProp({ type: AsnPropTypes.OctetString, optional: true })
	public domainInfo: Uint8Array
}

export class EasTicketAttestation extends AttestableObject implements Attestable {

	private signedAttestation: SignedOffchainAttestation;
	private signerAddress: string;
	private signerPublicKey: string;
	private signerKeyPair?: KeyPair;
	private decodedData?: {[fieldName: string]: any};
	private commitmentSecret?: bigint;
	private conferenceKeys?: KeyPair[];
	private crypto = new AttestationCrypto();

	/**
	 *
	 * @param schema The schema for the attestation. This must always be provided.
	 * @param signingConfig The EAS SDK config and signer - required only to create & revoke attestations.
	 * @param rpcMap A map of RPC nodes required for revocation checks
	 * @param issuerKeys A map of valid issuer keys for signature validation purposes
	 */
	constructor(
		private schema: TicketSchema,
		private signingConfig?: {
			EASconfig: {
				address: string // EAS resolver contract address
				version: string
				chainId: number
			},
			signer: Signer
		},
		private rpcMap?: {[chainId: number]: string},
		private issuerKeys?: KeysArray
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
	 * @param options
	 * @param commitmentType
	 */
	async createEasAttestation(data: {[key: string]: string|number}, options?: EasTicketCreationOptions, commitmentType = 'mail'){

		if (!this.signingConfig)
			throw new Error("Please provide valid signing config for this function.");

		this.signerAddress = await this.signingConfig.signer.getAddress();

		if (!this.signerAddress)
			new Error("Failed to get signer address");

		// New secret generated for each attestation
		this.commitmentSecret = undefined;

		const fieldData = this.schema.fields.map((field) => {

			if (!data[field.name])
				throw new Error("Value for field " + field.name + " was not provided");

			let value = data[field.name]

			if (field.isCommitment){

				// If there are multiple commitment fields, the same secret is used for all fields
				if (!this.commitmentSecret)
					this.commitmentSecret = this.crypto.makeSecret();

				value = this.createCommitment(value as string, commitmentType, this.commitmentSecret);
			}

			return {
				name: field.name,
				value,
				type: field.type
			}
		})

		const offchain = new Offchain(this.signingConfig.EASconfig);

		const schemaEncoder = new SchemaEncoder(this.getEasSchema());
		const encodedData = schemaEncoder.encodeData(fieldData);

		const newAttestation = await offchain.signOffchainAttestation({
			recipient: options?.recipient ?? '0x0000000000000000000000000000000000000000',
			// Unix timestamp of when attestation expires. (0 for no expiration)
			expirationTime: options?.validity?.to ?? 0,
			// Unix timestamp of current time
			time: options?.validity?.from ?? Math.round(Date.now() / 1000),
			nonce: 0,
			/*schema: "0x4677bc98bd107f75d03d13cf41e158e38f1b826502dd31f87bf384c1a888cbdc",*/
			schema:  options?.schema ?? "0x0000000000000000000000000000000000000000000000000000000000000000",
			revocable: true,
			refUID: options?.refUID ?? "0x0000000000000000000000000000000000000000000000000000000000000000",
			data: encodedData,
		}, this.signingConfig.signer as unknown as TypedDataSigner);

		const valid = offchain.verifyOffchainAttestationSignature(this.signerAddress, newAttestation)

		if (!valid)
			throw new Error("Attestation signature check failed!");

		this.signedAttestation = newAttestation;

		return this.getEasJson();
	}

	private createCommitment(commitmentValue: string, commitmentType: string, commitmentSecret: bigint){
		return "0x" + uint8tohex(this.crypto.makeCommitment(commitmentValue, this.crypto.getType(commitmentType), commitmentSecret))
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


	getEncoded(){
		return base64toBase64Url(zipAndEncodeToBase64(this.getEasJson()));
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
				this.decodedData[value.name] = dataArr[index].value.value;
				index++;
			}

			//this.decodedData["commitment"] = dataArr[index].value;
		}

		return this.decodedData;
	}

	getAttestationField(fieldName: string){

		const data = this.getAttestationData();

		if (!data[fieldName]) {
			throw new Error("The attestation does not contain data field '" + fieldName + "'");
		}

		return data[fieldName]
	}

	verifyIdCommitment(commitValue: string, commitSecret?: bigint, commitmentType = 'mail'){

		if (commitSecret)
			this.commitmentSecret = commitSecret;

		if (!this.commitmentSecret)
			throw new Error("Commitment secret required.");

		const calced = this.createCommitment(commitValue, commitmentType, this.commitmentSecret);

		const commit = this.getAttestationField("commitment");

		if (calced !== commit)
			throw new Error("Commitment verification failed.");
	}

	async validateEasAttestation(){

		this.checkAttestationIsLoaded();

		// Signature check
		this.verify();

		// Expiry check
		this.checkValidity();

		// EAS registry check to make sure attestation is not revoked
		if(this.signedAttestation.message.revocable)
			await this.checkRevocation()
	}

	private async checkRevocation(uid?: string){

		if (!uid)
			uid = this.getEasUid();

		const chainId = this.signedAttestation.domain.chainId;

		if (!this.rpcMap?.[chainId])
			throw new Error("RPC not provided for chain " + chainId);

		const eas = new EAS(this.signedAttestation.domain.verifyingContract, {signerOrProvider: new ethers.providers.JsonRpcProvider(this.rpcMap[chainId])});

		const revoked = await eas.getRevocationOffchain(this.signerAddress, uid);

		if (BigNumber.from(revoked).gt(0)) {
			const msg = "Attestation has been revoked :-(";
			//alert(msg);
			throw new Error(msg);
		}
	}

	async revokeEasAttestation(uid?: string){

		if (!uid)
			uid = this.getEasUid();

		if (!this.signingConfig)
			throw new Error("Please provide a valid signer");

		const eas = new EAS(this.signingConfig.EASconfig.address, {signerOrProvider: this.signingConfig.signer});

		const tx = await eas.revokeOffchain(uid);

		await tx.wait();
	}

	async bulkRevokeEasAttestations(uids: string[]){

		if (!this.signingConfig)
			throw new Error("Please provide a valid signer");

		const eas = new EAS(this.signingConfig.EASconfig.address, {signerOrProvider: this.signingConfig.signer});

		const tx = await eas.multiRevokeOffchain(uids);

		await tx.wait();
	}

	loadEasAttestation(attestation: SignedOffchainAttestation, keys?: KeysArray, commitmentSecret?: string){
		this.decodedData = undefined;
		this.commitmentSecret = commitmentSecret ? BigInt(commitmentSecret) : undefined;
		this.signedAttestation = attestation;

		this.processKeysParam(keys);
	}

	loadFromEncoded(
		base64url: string,
		keys?: KeysArray,
		commitmentSecret?: string){
		const decoded = decodeBase64ZippedBase64(base64UrltoBase64(base64url));

		this.loadEasAttestation(decoded.sig as SignedOffchainAttestation, keys, commitmentSecret)
	}

	getAsnEncoded(compressed = false){

		const abiEncoded = defaultAbiCoder.encode(
			this.signedAttestation.types.Attest.map((field) => field.type),
			this.signedAttestation.types.Attest.map((field) => this.signedAttestation.message[field.name])
		);

		const asnEmbedded = new EasAsnEmbeddedSchema();

		asnEmbedded.easAttestation = hexStringToUint8(abiEncoded);
		asnEmbedded.signatureValue = hexStringToUint8(joinSignature(this.signedAttestation.signature));

		const domainEncoded = defaultAbiCoder.encode(
			['string', "address", "uint256"],
			[
				this.signedAttestation.domain.version,
				this.signedAttestation.domain.verifyingContract,
				this.signedAttestation.domain.chainId
			]
		)
		asnEmbedded.domainInfo = hexStringToUint8(domainEncoded);

		const data =  AsnSerializer.serialize(asnEmbedded);

		if (!compressed)
			return data;

		return pako.deflate(data, {level: 9});
	}

	loadAsnEncoded(bytes: ArrayBuffer|Uint8Array, keys?: KeysArray, compressed = false){

		this.decodedData = undefined;
		this.commitmentSecret = undefined;

		if (compressed)
			bytes = pako.inflate(bytes);

		const asnEmbedded = AsnParser.parse(bytes, EasAsnEmbeddedSchema);

		const domainDecoded = defaultAbiCoder.decode(
			['string', "address", "uint256"],
			asnEmbedded.domainInfo
		);

		const domain: EIP712DomainTypedData = {
			name: "EAS Attestation",
			version: domainDecoded[0],
			verifyingContract: domainDecoded[1],
			chainId: domainDecoded[2]
		}

		// console.log("ABI Encoded bytes: ", "0x" + uint8tohex(new Uint8Array(asnEmbedded.easAttestation)));

		const abiDecoded = defaultAbiCoder.decode(ATTESTATION_TYPE.map((field) => field.type), "0x" + uint8tohex(new Uint8Array(asnEmbedded.easAttestation)));

		// console.log("Abi decoded: ", abiDecoded);

		const mappedDecodedValues = {};

		for (const [index, value] of ATTESTATION_TYPE.entries()){
			mappedDecodedValues[value.name] = abiDecoded[index];
		}

		const splitSignature = ethers.utils.splitSignature(new Uint8Array(asnEmbedded.signatureValue));

		this.signedAttestation = {
			domain: domain,
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

		this.processKeysParam(keys);
	}

	checkValidity(): boolean {

		const now = Math.round(Date.now() / 1000);

		if (now < this.signedAttestation.message.time)
			throw new Error("Attestation not yet valid.");

		if (this.signedAttestation.message.expirationTime > 0 && now > this.signedAttestation.message.expirationTime)
			throw new Error("Attestation has expired.");

		return true;
	}

	private processKeysParam(keys?: KeysArray){

		const data = this.getAttestationData();

		let conferenceId = data.eventId ?? data.devconId ?? "";

		if (!keys){
			if (!this.issuerKeys){
				throw new Error("No signing keys are defined");
			}
			keys = this.issuerKeys;
		}

		if (!keys[conferenceId]){
			if (!conferenceId || (conferenceId && !keys[""])){
				throw new Error(conferenceId ? "No key set for conference ID " + conferenceId :  "No default key set");
			}
			conferenceId = ""; // Use default key as fallback when no keys for the provided conference ID are set
		}

		const keyArray = keys[conferenceId];

		if (Array.isArray(keyArray)){
			this.conferenceKeys = keyArray;
		} else {
			this.conferenceKeys = [keyArray];
		}

		this.recoverSignerInfo();
	}

	private recoverSignerInfo(){

		const config = {
			version: this.signedAttestation.domain.version,
			address: this.signedAttestation.domain.verifyingContract,
			chainId: this.signedAttestation.domain.chainId
		};

		const offchain = new Offchain(config);

		const hash = ethers.utils._TypedDataEncoder.hash(offchain.getDomainTypedData(), {Attest: ATTESTATION_TYPE}, this.signedAttestation.message);

		this.signerPublicKey = ethers.utils.recoverPublicKey(hash, this.signedAttestation.signature);
		this.signerAddress = ethers.utils.recoverAddress(hash, this.signedAttestation.signature)
	}

	verify(): boolean {

		if (!this.conferenceKeys){
			throw new Error("Issuer keys are not defined");
		}

		for (const key of this.conferenceKeys){

			if (this.signerPublicKey.substring(2) === key.getPublicKeyAsHexStr()) {
				this.signerKeyPair = key;
				return true;
			}
		}

		throw new Error("Ticket signature is invalid");
	}

	getSignerKeyPair(){
		return this.signerKeyPair;
	}

	getCommitment(): Uint8Array {
		return hexStringToUint8(this.getAttestationField("commitment"));
	}

	getDerEncoding(): string {
		return uint8tohex(new Uint8Array(this.getAsnEncoded(false)));
	}

	protected commitment: Uint8Array;
	protected encoded: string;

	fromBytes(bytes:  ArrayBuffer|Uint8Array, keys: KeysArray){
		this.loadAsnEncoded(bytes, keys);
	}

}