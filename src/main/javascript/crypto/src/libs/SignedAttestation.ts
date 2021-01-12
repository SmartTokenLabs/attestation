import {AsnParser} from "@peculiar/asn1-schema";
import {MyAttestation} from "./../asn1/shemas/AttestationFramework";

export class SignedAttestation {
    constructor() {
        // const extension = AsnParser.parse(Buffer.from("30120603551d130101ff040830060101ff020101", "hex"), RedeemChequeShema);
        let str = "MIICdTCCAh2gAwIBEgIIa/zpJwRqwZswCQYHKoZIzj0CATAWMRQwEgYDVQQDDAtBbHBoYVdhbGxldDAiGA8yMDIxMDExMDEyNDgxNFoYDzIwMjEwMTEwMTM0ODE0WjA1MTMwMQYDVQQDDCoweDE4QTg4NDFDNEQ3NDhGQTUyOUM2NEY2MEQxMUJBMTBDNTU3RDhEMEEwggEzMIHsBgcqhkjOPQIBMIHgAgEBMCwGByqGSM49AQECIQD////////////////////////////////////+///8LzBEBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcEQQR5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmEg62ncmo8RlXaT7/A4RCKj9F7RIpoVUGZxH0I/7ENS4AiEA/////////////////////rqu3OavSKA7v9JejNA2QUECAQEDQgAE0CE0vCZb2J/Z1EStkyMfAXOWexLEAywTGokAmCDq8aeaVXvRmf3kVqt2muiDruMoZepQncgn5zHh9eFdA8u4JqNXMFUwUwYLKwYBBAGLOnN5ASgBAf8EQQQMF1i7zTEdXCPA641GBPhi1RAb5x58HDLt1VsnxMD2XS/tBaXZ2vlOaed/Kw+uhUZlvOHIa3ZU7vgMQwWLPHTbMAkGByqGSM49AgEDRwAwRAIgBUT0Erd7oA9mP/KL+Adn7+bGkWPwg12FVM9Ui+qwCEYCIAfsbIR2K1v00g/Db/V81JhNob3F98JRBXfigkR/dUmQ";
        let source: Uint8Array;
        if (typeof Buffer !== 'undefined') {
            source = Uint8Array.from(Buffer.from(str, 'base64'));
        } else {
            source = Uint8Array.from(atob(str), c => c.charCodeAt(0));
        }

        const extension = AsnParser.parse(source, MyAttestation);
        console.log("Extension:", extension);


    }

}
