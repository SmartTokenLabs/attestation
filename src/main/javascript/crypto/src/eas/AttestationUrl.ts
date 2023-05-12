
import * as pako from "pako";
import * as Base64 from "js-base64";
import {SignedOffchainAttestation} from "@ethereum-attestation-service/eas-sdk";
import {ethers} from "ethers";

export interface SignedOffchainAttestationV1
	extends Omit<SignedOffchainAttestation, "signature"> {
	r: string;
	s: string;
	v: number;
}

export interface AttestationShareablePackageObject {
	/** Signed typed data with attestation object */
	sig: SignedOffchainAttestation | SignedOffchainAttestationV1;
	/** Address of the signer */
	signer: string;
}

export type CompactAttestationShareablePackageObject = [
	version: string,
	chainId: number,
	verifyingContract: string,
	r: string,
	s: string,
	v: number,
	signer: string,
	uid: string,
	schema: string,
	recipient: string,
	time: number,
	expirationTime: number,
	refUID: string,
	revocable: boolean,
	data: string,
	nonce: number
];

export type CompactLightweightAttestationShareablePackageObject = [
	r: string,
	s: string,
	v: number,
	uid: string,
	recipient: string,
	time: number,
	expirationTime: number,
	refUID: string,
	revocable: boolean,
	data: string,
	nonce: number
];

export interface StaticSchemaInformation {
	domain: {
		version: string,
		chainId: number,
		verifyingContract: string,
	},
	schema: string,
	signer: string,
}

export function createURL(attPackage: AttestationShareablePackageObject) {
	const base64 = zipAndEncodeToBase64(attPackage);
	return `#attestation=${encodeURIComponent(base64)}`;
}

export function zipAndEncodeToBase64(
	qrPackage: AttestationShareablePackageObject,
	lightweight = false
) {
	const compacted = lightweight ?
		compactLightweightOffchainAttestationPackage(qrPackage) :
		compactOffchainAttestationPackage(qrPackage);

	const jsoned = JSON.stringify(compacted);

	const gzipped = pako.deflate(jsoned, { level: 9 });
	return Base64.fromUint8Array(gzipped);
}

export function decodeBase64ZippedBase64(
	base64: string,
	schemaInfo?: StaticSchemaInformation
): AttestationShareablePackageObject {
	const fromBase64 = Base64.toUint8Array(base64);

	const jsonStr = pako.inflate(fromBase64, { to: "string" });

	const compacted: CompactAttestationShareablePackageObject|CompactLightweightAttestationShareablePackageObject =
		JSON.parse(jsonStr);

	return schemaInfo ?
		uncompactLightweightOffchainAttestationPackage(compacted as CompactLightweightAttestationShareablePackageObject, schemaInfo) :
		uncompactOffchainAttestationPackage(compacted as CompactAttestationShareablePackageObject);
}

export function compactLightweightOffchainAttestationPackage(
	pkg: AttestationShareablePackageObject
): CompactLightweightAttestationShareablePackageObject {
	let { sig, signer } = pkg;

	if (isSignedOffchainAttestationV1(sig)) {
		sig = convertV1AttestationToV2(sig);
	}

	return [
		sig.signature.r,
		sig.signature.s,
		sig.signature.v,
		sig.uid,
		sig.message.recipient === ethers.constants.AddressZero
			? "0"
			: sig.message.recipient,
		Number(sig.message.time),
		Number(sig.message.expirationTime),
		sig.message.refUID === ethers.constants.HashZero ? "0" : sig.message.refUID,
		sig.message.revocable,
		sig.message.data,
		Number(sig.message.nonce),
	];
}


export function uncompactLightweightOffchainAttestationPackage(
	compacted: CompactLightweightAttestationShareablePackageObject,
	schemaInfo: StaticSchemaInformation
): AttestationShareablePackageObject {

	return {
		sig: {
			domain: {
				name: "EAS Attestation",
				version: schemaInfo.domain.version,
				chainId: schemaInfo.domain.chainId,
				verifyingContract: schemaInfo.domain.verifyingContract,
			},
			primaryType: "Attestation",
			types: {
				Attest: [
					{
						name: "schema",
						type: "bytes32",
					},
					{
						name: "recipient",
						type: "address",
					},
					{
						name: "time",
						type: "uint64",
					},
					{
						name: "expirationTime",
						type: "uint64",
					},
					{
						name: "revocable",
						type: "bool",
					},
					{
						name: "refUID",
						type: "bytes32",
					},
					{
						name: "data",
						type: "bytes",
					},
				],
			},
			signature: {
				r: compacted[0],
				s: compacted[1],
				v: compacted[2],
			},
			uid: compacted[3],
			message: {
				schema: schemaInfo.schema,
				recipient:
					compacted[4] === "0" ? ethers.constants.AddressZero : compacted[4],
				time: compacted[5],
				expirationTime: compacted[6],
				refUID:
					compacted[7] === "0" ? ethers.constants.HashZero : compacted[7],
				revocable: compacted[8],
				data: compacted[9],
				nonce: compacted[10],
			},
		},
		signer: schemaInfo.signer,
	};
}

export function compactOffchainAttestationPackage(
	pkg: AttestationShareablePackageObject
): CompactAttestationShareablePackageObject {
	let { sig, signer } = pkg;

	if (isSignedOffchainAttestationV1(sig)) {
		sig = convertV1AttestationToV2(sig);
	}

	return [
		sig.domain.version,
		sig.domain.chainId,
		sig.domain.verifyingContract,
		sig.signature.r,
		sig.signature.s,
		sig.signature.v,
		signer,
		sig.uid,
		sig.message.schema,
		sig.message.recipient === ethers.constants.AddressZero
			? "0"
			: sig.message.recipient,
		Number(sig.message.time),
		Number(sig.message.expirationTime),
		sig.message.refUID === ethers.constants.HashZero ? "0" : sig.message.refUID,
		sig.message.revocable,
		sig.message.data,
		Number(sig.message.nonce),
	];
}


export function uncompactOffchainAttestationPackage(
	compacted: CompactAttestationShareablePackageObject
): AttestationShareablePackageObject {
	return {
		sig: {
			domain: {
				name: "EAS Attestation",
				version: compacted[0],
				chainId: compacted[1],
				verifyingContract: compacted[2],
			},
			primaryType: "Attestation",
			types: {
				Attest: [
					{
						name: "schema",
						type: "bytes32",
					},
					{
						name: "recipient",
						type: "address",
					},
					{
						name: "time",
						type: "uint64",
					},
					{
						name: "expirationTime",
						type: "uint64",
					},
					{
						name: "revocable",
						type: "bool",
					},
					{
						name: "refUID",
						type: "bytes32",
					},
					{
						name: "data",
						type: "bytes",
					},
				],
			},
			signature: {
				r: compacted[3],
				s: compacted[4],
				v: compacted[5],
			},
			uid: compacted[7],
			message: {
				schema: compacted[8],
				recipient:
					compacted[9] === "0" ? ethers.constants.AddressZero : compacted[9],
				time: compacted[10],
				expirationTime: compacted[11],
				refUID:
					compacted[12] === "0" ? ethers.constants.HashZero : compacted[12],
				revocable: compacted[13],
				data: compacted[14],
				nonce: compacted[15],
			},
		},
		signer: compacted[6],
	};
}

export function isSignedOffchainAttestationV1(
	attestation: SignedOffchainAttestation | SignedOffchainAttestationV1
): attestation is SignedOffchainAttestationV1 {
	return "v" in attestation && "r" in attestation && "s" in attestation;
}

export function convertV1AttestationToV2(
	attestation: SignedOffchainAttestationV1
): SignedOffchainAttestation {
	const { v, r, s, ...rest } = attestation;
	return {
		...rest,
		signature: {
			v,
			r,
			s,
		},
	};
}