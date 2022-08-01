import * as asn1_schema_1 from "@peculiar/asn1-schema";
import {AsnParser, AsnPropTypes, AsnSerializer} from "@peculiar/asn1-schema";
import {base64ToUint8array, hexStringToUint8, uint8arrayToBase64, uint8tohex} from "../libs/utils";
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

export declare type EncodingType = "hex" | "base64";

export class SchemaGenerator {

	jsonSchema: any;

	generatedSchema: any;

	private static __decorate = function (decorators: any, target: any, key: any, desc: any) {
		var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
		// @ts-ignore
		if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
		else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
		return c > 3 && r && Object.defineProperty(target, key, r), r;
	};

	constructor(jsonSchema: SchemaDefinitionInterface) {
		this.jsonSchema = jsonSchema;

		this.generatedSchema = this.generateSchema();
	}

	private generateSchema(): any {

		let Schema: any = class {};

		for (let i in this.jsonSchema){

			if (this.jsonSchema[i].items){

				let childSchemaGenerator: any = new SchemaGenerator(this.jsonSchema[i].items);
				let childSchema = childSchemaGenerator.getSchemaType();
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

	getSchemaType(){
		return this.generatedSchema;
	}

	getSchemaObject(){
		return new this.generatedSchema();
	}

	serialize(object: Object): Uint8Array {
		return new Uint8Array(AsnSerializer.serialize(object));
	}

	serializeAndFormat(object: Object, encoding: EncodingType = "hex"){

		let uint = this.serialize(object);

		if (encoding === "hex"){
			return uint8tohex(uint);
		} else {
			return uint8arrayToBase64(uint);
		}
	}

	parse(data: Uint8Array|string, encoding: EncodingType = "hex"): any {

		if (!(data instanceof Uint8Array)){
			if (encoding === "hex"){
				data = hexStringToUint8(data);
			} else {
				data = base64ToUint8array(data);
			}
		}

		return AsnParser.parse(data, this.generatedSchema);
	}
}