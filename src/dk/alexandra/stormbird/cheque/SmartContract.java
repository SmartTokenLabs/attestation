package dk.alexandra.stormbird.cheque;

import java.io.IOException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.math.ec.ECPoint;

public class SmartContract {
  private final Crypto crypto;

  public SmartContract(Crypto crypto) {
    this.crypto = crypto;
  }

  public boolean cashCheque(X509Certificate cert, Proof proof, SignedCheque cheque) throws IOException {
    try {
      cert.checkValidity();
      cert.verify(cert.getPublicKey(), "BC");
    } catch (Exception e) {
      // Certificate is not valid
      e.printStackTrace();
      return false;
    }
    // Retrieve string
    byte[] byteIdentifier = cert.getExtensionValue(Util.OID_OCTETSTRING);
    ASN1InputStream input = new ASN1InputStream(byteIdentifier);
    DEROctetString object = (DEROctetString) input.readObject();
    // Need to decode twice since the standard ASN1 encodes the octet string in an octet string
    input = new ASN1InputStream(object.getOctets());
    object = (DEROctetString) input.readObject();
    byte[] decodedIdentifier = crypto.decodePoint(object.getOctets()).getEncoded();
    if (!Arrays.equals(decodedIdentifier, proof.base.value)) {
      System.err.println("Identity of proof and cert does not match");
      return false;
    }
    byte[] decodedRiddle = crypto.decodePoint(cheque.cheque.riddle.value).getEncoded();
    if (!Arrays.equals(decodedRiddle, proof.riddle.value)) {
      System.err.println("The riddle of the proof and cheque does not match");
      return false;
    }
    if (!crypto.verifyProof(Arrays.asList(
        proof.base.value, proof.riddle.value, proof.challengePoint.value, proof.reponseValue.value))) {
      System.err.println("Proof did not verify");
      return false;
    }
    return true;
  }
}
