import {base64ToUint8array, uint8toBuffer, uint8tohex} from './libs/utils';
import {readFileSync} from "fs";
import {Attestation} from "./libs/Attestation";
import {AttestationRequest} from "./libs/AttestationRequest";
import {KeyPair} from "./libs/KeyPair";
import {AttestedObject} from "./libs/AttestedObject";
import {UseToken} from "./asn1/shemas/UseToken";
import {PrivateKeyInfo, SignedInfo, PublicKeyInfoValue} from "./asn1/shemas/AttestationFramework";
import {AsnParser} from "@peculiar/asn1-schema";
import {SignedIdentityAttestation} from "./libs/SignedIdentityAttestation";
import {Eip712Validator} from "./libs/Eip712Validator";
import {Eip712AttestationRequest} from "./libs/Eip712AttestationRequest";
import {AttestationCrypto} from "./libs/AttestationCrypto";
import {IdentifierAttestation} from "./libs/IdentifierAttestation";
import {Authenticator} from "./Authenticator";

const PREFIX_PATH = '../../../../build/test-results/';

describe("Utils tests", () => {
    test('uint8tohex test', () => {
        expect(uint8tohex(new Uint8Array([1,2]))).toBe("0102")
    })
});

describe("Attestation test", () => {

    // const receiverPubPEM = readFileSync(PREFIX_PATH + 'receiver-pub.pem', 'utf8');

    const receiverPrivPEM = readFileSync(PREFIX_PATH + 'receiver-priv.pem', 'utf8');
    const attestorPrivPEM = readFileSync(PREFIX_PATH + 'attestor-priv.pem', 'utf8');
    let receiverKey = KeyPair.privateFromPEM(receiverPrivPEM);
    //console.log('receiverKey.getAddress(): ' + receiverKey.getAddress());

    // const receiverPubPEM = readFileSync(PREFIX_PATH + 'receiver-pub.pem', 'utf8');
    // const receiverPubUint8 = base64ToUint8array(receiverPubPEM);
    // let publicKeyObj: PublicKeyInfoValue = AsnParser.parse(uint8toBuffer( receiverPubUint8), PublicKeyInfoValue);
    // let receiverPubKey = KeyPair.publicFromUint(new Uint8Array(publicKeyObj.publicKey));
    // console.log('receiverKey.getAddress(): ' + receiverPubKey.getAddress());

    let attestationRequestJson = readFileSync(PREFIX_PATH + 'attestation-request.pem', 'utf8');
    // const attestationRequestUint8 = base64ToUint8array(attestationRequestPem);
    attestationRequestJson = attestationRequestJson.split(/\r?\n/).join('');
    let ATTESTOR_DOMAIN = "http://wwww.attestation.id"

    let attestRes = Authenticator.createAttest(attestorPrivPEM,'AlphaWallet', 60*60*1000, attestationRequestJson, ATTESTOR_DOMAIN);

    console.log(attestRes + '-------');




});
/*
describe("Keys decode test", () => {

    const signedTokenDER = readFileSync(PREFIX_PATH + 'signed-devcon-ticket.der');

    const receiverPubPEM = readFileSync(PREFIX_PATH + 'receiver-pub.pem', 'utf8');
    const receiverPrivPEM = readFileSync(PREFIX_PATH + 'receiver-priv.pem', 'utf8');

    const receiverPubUint8 = base64ToUint8array(receiverPubPEM);
    const receiverPrivUint8 = base64ToUint8array(receiverPrivPEM);

    let privateKeyObj: PrivateKeyInfo = AsnParser.parse(uint8toBuffer( receiverPrivUint8), PrivateKeyInfo);
    let publicKeyObj: PublicKeyInfoValue = AsnParser.parse(uint8toBuffer( receiverPubUint8), PublicKeyInfoValue);

});

describe("SignedIdentityAttestation test", () => {


    const attestorPubPEM = readFileSync(PREFIX_PATH + 'attestor-pub.pem', 'utf8');
    // const attestorPubUint8 = base64ToUint8array(attestorPubPEM);
    // let publicKeyObj: PublicKeyInfoValue = AsnParser.parse(uint8toBuffer( attestorPubUint8), PublicKeyInfoValue);
    // let attestorPubKey = KeyPair.publicFromUint(publicKeyObj.publicKey);
    let attestorPubKey = KeyPair.publicFromBase64(attestorPubPEM);


    const attestationPEM = readFileSync(PREFIX_PATH + 'attestation.pem', 'utf8');
    const attestationUint8 = base64ToUint8array(attestationPEM);

    let signedAttest = SignedIdentityAttestation.fromBytes(attestationUint8, attestorPubKey);

});

describe("AttestedObject decode test", () => {

    let token = '{"signatureInHex":"0x2a61de0341d1fc5549adbf93e07c57b5289c837ebe3143f03937ee46b933b2602c73898fad79faf295477b43bd6f3639886b97a0b43b1aadde3b68fb533693a31b","jsonRpc":"2.0","chainId":3,"jsonSigned":"{\\"types\\":{\\"EIP712Domain\\":[{\\"name\\":\\"name\\",\\"type\\":\\"string\\"},{\\"name\\":\\"version\\",\\"type\\":\\"string\\"},{\\"name\\":\\"chainId\\",\\"type\\":\\"uint256\\"},{\\"name\\":\\"verifyingContract\\",\\"type\\":\\"address\\"},{\\"name\\":\\"salt\\",\\"type\\":\\"bytes32\\"}],\\"Authentication\\":[{\\"name\\":\\"payload\\",\\"type\\":\\"string\\"},{\\"name\\":\\"description\\",\\"type\\":\\"string\\"},{\\"name\\":\\"timestamp\\",\\"type\\":\\"uint256\\"}]},\\"domain\\":{\\"name\\":\\"devcon.org\\",\\"version\\":\\"0.1\\",\\"chainId\\":3,\\"salt\\":\\"0x8e38ac3215914d84fff6534769f56862317be5dbe7c878a029612e546488e590\\"},\\"primaryType\\":\\"Authentication\\",\\"message\\":{\\"payload\\":\\"3082037e30819b300d020106020561376a9dfe020100044104289655c4c1176e44996415a73544d7ff989ebbc194a9fd1bc7f6b4b413c5e9062c90005a309058843397b2642dddcb24fd37cc676c1d99f4642bb78f08e2369203470030440220702caffde4d3d9a345b4d470c17f2662b19d8a68daf3a16bb1455fa786318b30022068e3f8795548347e7133c0aff4e543772386dc1c54ab23d540eb8353d3da0bda308202753082021da00302011202088ec1a8ce3f8a7680300906072a8648ce3d020130163114301206035504030c0b416c70686157616c6c65743022180f32303231303232343231353832385a180f32303231303232343232353832385a30353133303106035504030c2a307832463231444331324444343342443135423836363433333332303431414239373031303335374437308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f3044042000000000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000000704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101034200042f196ec33ad04c6398fe8eef1a84d8855397641bb4cbbbcf576e3baa34c516a51b2eac6b201dd24950b6513cbd85f6bd1a11b7bad511343d9dadeccb30f72642a35730553053060b2b060104018b3a737901280101ff04410413b6fbd4923141fd9faaf9ca1a1e16ea58359770d4636d277ee54711e612c2942e7c8aa9de6c5465808ac4e50897b56ead90a55dfc29492283e55c79c801f671300906072a8648ce3d02010347003044022046fb79772444157712521661bff779e567f45572176a658910ff770182caffeb022064f98592a14dc38b7f7f70411345e3fd700244289fa830978acf2d2f2ec6cd48306504202e4fe5825939c64b451b3afe590873cf9b8b09e8d6e9f151147d71bfd1772a3e0441040081fe8288a3437fef9d1435cd7e2f6e76a5159ffe99fde84ef644bf6ffd8871038a83ec561e90599173b645a910fe6c681203b0e8b3afbeefe4749b67425373\\",\\"description\\":\\"Single-use authentication\\",\\"timestamp\\":1614203910314}}"}';

    new Eip712Validator().validateRequest(token);

});

describe("AttestedObject test", () => {

    // const attestedObject = AttestedObject.fromBytes( new Uint8Array(signedTokenDER), UseToken, KeyPair.privateFromKeyInfo(privateKeyObj) );

});

// test('should return true given internal link', () => {
//     expect(isInternalLink('/some-page')).toBe(true)
// })
*/
