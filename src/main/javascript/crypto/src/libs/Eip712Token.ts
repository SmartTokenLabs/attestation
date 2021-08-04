import {Eip712Validator} from "./Eip712Validator";
import {KeyPair} from "./KeyPair";

// export interface Eip712DomainData: {[index: string]:string|number}  = {
export interface Eip712DomainData {
    name: string,
    version: string,
    chainId: number,
    verifyingContract: string,
    salt: string
}

export interface Eip712UserData {
    description: string,
    identifier: string,
    payload: string,
    timestamp: string,
    address?: string
}

export class Eip712Token extends Eip712Validator {
    protected eip712DomainData: Eip712DomainData;
    protected data: Eip712UserData;
    protected requestorKeys: KeyPair;
}
