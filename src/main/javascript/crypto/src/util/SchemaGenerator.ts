import * as asn1_schema_1 from "@peculiar/asn1-schema";
import {AsnParser, AsnPropTypes, AsnSerializer} from "@peculiar/asn1-schema";
import {hexStringToUint8, uint8tohex} from "../libs/utils";
import {AsnItemType, AsnRepeatType, IAsn1PropOptions} from "@peculiar/asn1-schema/build/types/decorators";
import {IAsnConverter} from "@peculiar/asn1-schema/build/types/types";

interface SchemaDefinitionInterface {
	[key: string]: SchemaItemInterface
}

interface SchemaItemInterface {
	name?: string;
	items?: SchemaDefinitionInterface,
	type?: AsnItemType | string;
	optional?: boolean;
	defaultValue?: any;
	context?: number;
	implicit?: boolean;
	converter?: IAsnConverter;
	repeated?: AsnRepeatType;
}

export class SchemaGenerator {

	jsonSchema: any;

	schemaObject: any;

	private static __decorate = function (decorators: any, target: any, key: any, desc: any) {
		var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
		// @ts-ignore
		if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
		else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
		return c > 3 && r && Object.defineProperty(target, key, r), r;
	};

	constructor(jsonSchema: SchemaDefinitionInterface = {
		ticket: {
			name: "Ticket",
			items: {
				devconId: {
					type: "Utf8String",
					optional: false
				},
				ticketIdNumber: {
					type: "Integer",
					optional: true
				},
				ticketIdString: {
					type: "Utf8String",
					optional: true
				},
				ticketClass: {
					type: "Integer",
					optional: false
				},
				linkedTicket: {
					name: "Linked Ticket",
					items: {
						devconId: {
							type: "Utf8String",
							optional: false
						},
						ticketIdNumber: {
							type: "Integer",
							optional: true
						},
						ticketIdString: {
							type: "Utf8String",
							optional: true
						},
						ticketClass: {
							type: "Integer",
							optional: false
						}
					}
				}
			}
		},
		commitment: {
			type: AsnPropTypes.OctetString,
			optional: true
		},
		signatureValue: {
			type: AsnPropTypes.BitString,
			optional: false
		}
	}) {
		this.jsonSchema = jsonSchema;

		this.schemaObject = this.generateSchema();
	}

	private generateSchema(): any {

		let Schema: any = class {};

		for (let i in this.jsonSchema){

			if (this.jsonSchema[i].items){

				let childSchemaGenerator: any = new SchemaGenerator(this.jsonSchema[i].items);
				let childSchema = childSchemaGenerator.getSchemaObject();

				Schema.prototype[i] = new childSchema();

				SchemaGenerator.__decorate([
					(asn1_schema_1.AsnProp)(this.getDecoratorOptions({ type: childSchema }))
				], Schema.prototype, i, void 0);

			} else {
				SchemaGenerator.__decorate([
					(asn1_schema_1.AsnProp)(this.getDecoratorOptions(this.jsonSchema[i]))
				], Schema.prototype, i, void 0);
			}

		}

		return Schema;
	}

	private getDecoratorOptions(item: SchemaItemInterface){

		let type: AsnPropTypes;

		if (typeof item.type === "string"){
			if (!(item.type in AsnPropTypes))
				throw new Error("Non-existent AsnPropType " + item.type);

			type = AsnPropTypes[item.type as any] as unknown as AsnPropTypes;
		} else {
			type = item.type as AsnPropTypes;
		}

		let decoratorOptions: IAsn1PropOptions = {
			type: type,
			optional: item.optional,
			defaultValue: item.defaultValue,
			context: item.context,
			implicit: item.implicit,
			converter: item.converter,
			repeated: item.repeated
		}

		return decoratorOptions;
	}

	getSchemaObject(){
		return this.schemaObject;
	}


}

export class Meh {

	meh() {

		let schemaGenerator = new SchemaGenerator();

		let GeneratedSchema = schemaGenerator.getSchemaObject();

		console.log("The full schema object");
		console.log(GeneratedSchema);

		let currentSchema = new GeneratedSchema();

		currentSchema.ticket.devconId = "6";
		currentSchema.ticket.ticketIdNumber = 10;
		currentSchema.ticket.ticketClass = 1;

		currentSchema.ticket.linkedTicket.devconId = "6";
		currentSchema.ticket.linkedTicket.ticketIdNumber = 10;
		currentSchema.ticket.linkedTicket.ticketClass = 1;

		currentSchema.signatureValue = new Uint8Array(hexStringToUint8("0xb135ded73c021184158fa6ea91eff0a97753f27163f3b35a57d3fac57146bf0a45795224fefb95edde7dd55a1554829b5be20f3e39b1fb27a52bd63972d1e89c1c"));

		console.log("Populated schema object");
		console.log(currentSchema);

		let encoded = AsnSerializer.serialize(currentSchema);

		console.log(uint8tohex(new Uint8Array(encoded)));

		let decoded = AsnParser.parse(encoded, GeneratedSchema);

		console.log(decoded);
	}
}