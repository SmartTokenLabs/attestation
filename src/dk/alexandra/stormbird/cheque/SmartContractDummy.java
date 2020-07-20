package dk.alexandra.stormbird.cheque;

import dk.alexandra.stormbird.cheque.asnobjects.RedeemCheque;
import dk.alexandra.stormbird.cheque.asnobjects.SignedCheque;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;

public class SmartContractDummy {
    private final Crypto crypto;

    public SmartContractDummy(Crypto crypto) {
      this.crypto = crypto;
    }

    public boolean cashCheque(X509Certificate cert, RedeemCheque redeem, SignedCheque cheque) throws IOException {
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
      if (!Arrays.equals(decodedIdentifier, redeem.proof.base.value)) {
        System.err.println("Identity of proof and cert does not match");
        return false;
      }
      byte[] decodedRiddle = crypto.decodePoint(cheque.cheque.riddle.value).getEncoded();
      if (!Arrays.equals(decodedRiddle, redeem.proof.riddle.value)) {
        System.err.println("The riddle of the proof and cheque does not match");
        return false;
      }
      if (!crypto.verifyProof(Arrays.asList(
          redeem.proof.base.value, redeem.proof.riddle.value, redeem.proof.challengePoint.value, redeem.proof.reponseValue.value))) {
        System.err.println("Proof did not verify");
        return false;
      }
      // todo handle the rest of redeem, i.e. verify signature
      return true;
    }
}
