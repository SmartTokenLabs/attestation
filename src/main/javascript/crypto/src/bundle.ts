import {Authenticator} from "./Authenticator";
import {Eip712AttestationRequest} from "./libs/Eip712AttestationRequest";
import {AttestationCrypto} from "./libs/AttestationCrypto";
import {IntegrationExample} from "./IntegrationExample";
import {SchemaGenerator} from "./util/SchemaGenerator";

(window as any).Authenticator = Authenticator;
(window as any).Attest = Eip712AttestationRequest;
(window as any).AttestationCrypto = AttestationCrypto;
(window as any).IntegrationExample = IntegrationExample;
(window as any).SchemaGenerator = SchemaGenerator;