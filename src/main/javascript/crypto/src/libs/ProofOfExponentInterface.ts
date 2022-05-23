import {Point} from "./Point";

export interface ProofOfExponentInterface {
    getPoint(): Point;
    getChallengeResponse(): bigint;
    getNonce(): Uint8Array;
    getDerEncoding(): string;
}
