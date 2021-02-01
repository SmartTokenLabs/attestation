import {Point} from "./Point";

export interface ProofOfExponentInterface {
    getPoint(): Point;
    getChallenge(): bigint;
    getDerEncoding(): string;
}
