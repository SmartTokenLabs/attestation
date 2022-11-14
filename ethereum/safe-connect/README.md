
# SolRsaVerify

# Usage

First you'll need an RSA private key. You can generate one using the
`openssl` cli:


    $ openssl genrsa -out private.pem 1024


Next lets sign a message:


    $ echo -n "hello world" | openssl dgst -sha256 -sign private.pem | xxd -p | tr -d \\n
    00d5380ea463dcb195e887bd900c2e25098401378d6da2e97e56ef1b984e6a67959f7adc662727e0c1e3ea3580caecba6a69925eec3704413e2192b0ff40f4711d424e4e1ecc6128534a2527c04bb1576c4582a589559a8ff9ad2bfd5f09f856dfefd90cd0464dee63f7b10d0b5ef69c389bc4ef4a9d35254fcad5ad246cc6a3%


We pass the string "hello world" to openssl to sign it and then to `xxd` to
convert from binary to hex and finally to `tr` to truncate newlines.

Now let's extract the public key from the private key:


    $ openssl rsa -in private.pem -outform PEM -pubout -out public.pem


And finally we need to extract `n` (the modulus) from the public key:


    $  openssl asn1parse -inform TXT -i -in public.pem -strparse 18
    0:d=0  hl=3 l= 137 cons: SEQUENCE
    3:d=1  hl=3 l= 129 prim:  INTEGER           :B793F2F926170FAD768F8B1A5769A2243B4CDCAC4780194F59B39E1A2ABC3BB8EA42DB495D17BEC7F7072A11ED4FA510E75A7886A5DB6F71B7AFCA0090CA079889D18AF0669829ED29A8E21D0C09BD19CAAF2FE2CC8121BFC5687AC6698E3022F468A481426486CAD263BE1A119491E034A6E1AB78F19C066D4145A50F9ECFF7
    135:d=1  hl=2 l=   3 prim:  INTEGER           :010001


Now we can call `SolRsaVerify.pkcs1Sha256VerifyRaw` and verify the signature:

````javascript
const message = web3.utils.asciiToHex("hello world");
const modulus = "0xFAEEFC2BE95C7BD5FA106BF2304D2FF1471310C303AAF05B1C68BB205564E3B7195C162002B3BB2D529AEFBD48FB810A978F047F87978DCC28680A56692A396ECF92A69BE1B78031ECB0FE0B0E4B37FC1837A7696499A30142F435745D15ADDE7A1201C6DA20FF797A9B1492464BB6FDB18BBF50AFCC48881566EC1CD3298795";
const exponent= "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001";
const signature = "0x1cf96164b68c76598e618d3fb70599e9360f143f274a5a19616068482afb4ab9529e59457fee16b60494dfcfbbc637cb8af5ba6396afc1851158909382cb4294269778085ba3c4cba01aba3ed44599f9f3e64da57750e78c2c38bd3f2f03984d62b6506252f612e43d4d1040ae4da685b050fe27d9cb6457f8269cf17d385536";

const contract = await SolRsaVerify.new();
const result = await contract.pkcs1Sha256VerifyRaw(message, signature, exponent, modulus);
if (result == 0) {
  console.log("Signature is valid");
} else {
  console.log("Signature is invalid");
}
````

(Note: don't forget to prefix the hex values with 0x)


### gas estimation
- VerifyLinkAttestation: "319355"

With console: "310403" gas
Without console: "281549"

 277258

- RSAVerification: 192166
  

  RSA txResult ==> 114049
  RSA txResult ==> 48376


  RSA txResult ==> 48157
  RSA txResult ==> 37888 ===> join function 10269 gas


