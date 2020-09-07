package dk.alexandra.stormbird.cheque;

import com.objsys.asn1j.runtime.Asn1BerDecodeBuffer;
import com.objsys.asn1j.runtime.Asn1BitString;
import com.objsys.asn1j.runtime.Asn1DerDecodeBuffer;
import com.objsys.asn1j.runtime.Asn1OctetString;
import dk.alexandra.stormbird.cheque.asnobjects.MyAttestation;
import dk.alexandra.stormbird.cheque.asnobjects.Proof;
import dk.alexandra.stormbird.cheque.asnobjects.RedeemCheque;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.math.ec.ECPoint;

public class Receiver {
  private final String address;
  private final Crypto crypto;
  private final KeyPair keys;
  private static final X9ECParameters curve = SECNamedCurves.getByName (Crypto.ECDSA_CURVE);
  private static final ECDomainParameters domain = new ECDomainParameters (curve.getCurve (), curve.getG (), curve.getN (), curve.getH ());

  public Receiver(String address, KeyPair keys, Crypto crypto) {
    this.address = address;
    this.keys = keys;
    this.crypto = crypto;
  }

  /**
   * DER encoded CSR with ECDSA SHA256 spec
   */
  public CSRAndSecret createCSR(String identity, int type) throws Exception {
    BigInteger secret = crypto.makeRandomExponent();
    ECPoint hashedIdentity = crypto.hashIdentifier(type, identity);
    ECPoint identifier = hashedIdentity.multiply(secret);

    // Encode ETH address as CommonName
    X509Name name = new X509Name("CN=" + address);
    byte[] encoding = identifier.getEncoded(false);
    ASN1Set attributes = new DERSet(new ASN1Encodable[]{
        new DERSequence(new ASN1Encodable[]{
            // Encode encrypted identity as an Octet string attribute
            new ASN1ObjectIdentifier(Util.OID_OCTETSTRING), new DERSet(new DEROctetString(encoding))
        })
//        , new DERSequence(new ASN1Encodable[]{
//            // Integer
//            new DERObjectIdentifier("1.3.6.1.4.1.1466.115.121.1.27"), new DERSet( new DERInteger(type))
//          new DEROctetString(secret), new DERInteger(type)
    });
    // OID for ECDSA with SHA256
    PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Util.OID_SHA256ECDSA, name, keys.getPublic(), attributes, keys.getPrivate());
    // Construct proof of knowledge of secret
    List<byte[]> proofBytes = crypto.computeProof(hashedIdentity, identifier, secret);
    Proof proof = new Proof(new Asn1OctetString(proofBytes.get(0)), new Asn1OctetString(proofBytes.get(1)),
        new Asn1OctetString(proofBytes.get(2)), new Asn1OctetString(proofBytes.get(3)));

    byte[] encodedProofBytes = Util.getAsnBytes(Arrays.asList(proof));
    byte[] signature = crypto.signBytes(Util.getBytes(Arrays.asList(encodedProofBytes, csr.getEncoded())), keys);
    return new CSRAndSecret(csr, secret, proof, signature);
  }

  public RedeemCheque redeemCheque(ChequeAndSecret chequeAndSecret, X509Certificate cert, BigInteger secret, KeyPair keys) throws Exception {
    ECPoint decodedRiddle = crypto.decodePoint(chequeAndSecret.getCheque().cheque.riddle.value);
    BigInteger x = secret.modInverse(crypto.curveOrder).multiply(chequeAndSecret.getSecret()).mod(crypto.curveOrder);
    // It now holds that identifier.multiply(x) = riddle
    ECPoint identifier = crypto.decodePoint(Util.getIdentifierFromCert(cert));
    List<byte[]> proofBytes = crypto.computeProof(identifier, decodedRiddle, x);
    Proof proof = new Proof(new Asn1OctetString(proofBytes.get(0)), new Asn1OctetString(proofBytes.get(1)),
        new Asn1OctetString(proofBytes.get(2)), new Asn1OctetString(proofBytes.get(3)));

    // We decode the cert into an Attestation object since we know it is an attestation and now a general cert
    MyAttestation attestation = new MyAttestation();
    Asn1BerDecodeBuffer buffer = new Asn1DerDecodeBuffer(cert.getEncoded());
    attestation.decode (buffer);

    byte[] signature = crypto.signBytes(Util.getAsnBytes(Arrays.asList(chequeAndSecret.getCheque(), attestation, proof)), keys);
    RedeemCheque redeemCheque = new RedeemCheque(chequeAndSecret.getCheque(), attestation, proof, new Asn1BitString(signature));
    return redeemCheque;
  }

//  private void makeASN1Redeem(SignedCheque cheque, X509Certificate cert, List<byte[]> proof) {
//    ASN1Sequence unsigned = new DERSequence(new ASN1Encodable[]{
//        new DERSequence(new ASN1Encodable[]{
//            // Signed cheque
//            new DERSequence(new ASN1Encodable[] {
//                // Cheque
//                new DERSequence(new ASN1Encodable[] {
//                    new DERInteger((int) cheque.cheque.amount.value),
//                    new DEROctetString(cheque.cheque.riddle.value)
//                }),
//                new DERBitString(cheque.publicKey.value),
//                new DERBitString(cheque.signatureValue.value)
//            }),
//            new DER
//            cert,
//            proof
////            new DERObjectIdentifier(Util.OID_OCTETSTRING), new DEROctetString(encoding)
//        })
////        , new DERSequence(new ASN1Encodable[]{
////            // Integer
////            new DERObjectIdentifier("1.3.6.1.4.1.1466.115.121.1.27"), new DERSet( new DERInteger(type))
////          new DEROctetString(secret), new DERInteger(type)
//    });
//  }
}
