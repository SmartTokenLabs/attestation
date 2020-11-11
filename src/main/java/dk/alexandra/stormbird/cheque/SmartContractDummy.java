package dk.alexandra.stormbird.cheque;

import com.objsys.asn1j.runtime.Asn1GeneralizedTime;
import dk.alexandra.stormbird.cheque.asnobjects.RedeemCheque;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import sun.security.x509.X509CertImpl;

public class SmartContractDummy {
    private final Crypto crypto;

    public SmartContractDummy(Crypto crypto) {
      this.crypto = crypto;
    }

    public boolean cashCheque(RedeemCheque redeem, PublicKey caPublicKey, PublicKey senderPublicKey) throws Exception {
      // CHECK Verify CA signature on cert
      InputStream inStream = new ByteArrayInputStream(Util.encodeASNObject(redeem.attestation));
      X509Certificate cert = new X509CertImpl(inStream);
      try {
        cert.checkValidity();
        cert.verify(caPublicKey, "BC");
      } catch (Exception e) {
        // Certificate is not valid
        e.printStackTrace();
        return false;
      }

      // CHECK verify signature on RedeemCheque is from the same party that holds the attestation
      if (!crypto.verifyBytes(Util.getAsnBytes(Arrays.asList(redeem.signedCheque, redeem.attestation, redeem.proof)), redeem.signatureValue.value, cert.getPublicKey())) {
        System.err.println("The signature on RedeemCheque is not valid");
        return false;
      }

      // CHECK verify signature on the cheque against the sender's public key
      if (!crypto.verifyBytes(Util.getAsnBytes(Arrays.asList(redeem.signedCheque.cheque)), redeem.signedCheque.signatureValue.value, senderPublicKey)) {
        System.err.println("The signature on the cheque is not valid");
        return false;
      }
      // Retrieve string
      byte[] byteIdentifier = cert.getExtensionValue(Util.OID_OCTETSTRING);
      ASN1InputStream input = new ASN1InputStream(byteIdentifier);
      DEROctetString object = (DEROctetString) input.readObject();
      // Need to decode twice since the standard ASN1 encodes the octet string in an octet string
      input = new ASN1InputStream(object.getOctets());
      object = (DEROctetString) input.readObject();

      // CHECK: verify the identity of the proof and the attestation matcher
      byte[] decodedIdentifier = crypto.decodePoint(object.getOctets()).getEncoded(false);
      if (!Arrays.equals(decodedIdentifier, redeem.proof.base.value)) {
        System.err.println("Identity of proof and cert does not match");
        return false;
      }

      // CHECK: verify that the riddle of the proof and cheque matches
      byte[] decodedRiddle = crypto.decodePoint(redeem.signedCheque.cheque.riddle.value).getEncoded(false);
      if (!Arrays.equals(decodedRiddle, redeem.proof.riddle.value)) {
        System.err.println("The riddle of the proof and cheque does not match");
        return false;
      }

      // CHECK: verify the proof is valid
      if (!crypto.verifyProof(Arrays.asList(
          redeem.proof.base.value, redeem.proof.riddle.value, redeem.proof.challengePoint.value, redeem.proof.reponseValue.value))) {
        System.err.println("Proof did not verify");
        return false;
      }

      // CHECK: that the cheque is still valid
      String ca = redeem.signedCheque.cheque.validity.notAfter.getElemName();
      if (redeem.signedCheque.cheque.validity.notAfter.getElemName() != "generalizedTime" ||
          redeem.signedCheque.cheque.validity.notBefore.getElemName() != "generalizedTime") {
        throw new UnsupportedOperationException("UTCTime handling has not been implemented, you need generalized time");
      }
      DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyyMMddHHmmss"); // GeneralizedTime
      String currentTime = LocalDateTime.now().format(dtf);
      String notAfterVal = ((Asn1GeneralizedTime) redeem.signedCheque.cheque.validity.notAfter.getElement()).value;
      String notBeforeVal = ((Asn1GeneralizedTime) redeem.signedCheque.cheque.validity.notBefore.getElement()).value;
      // Because of the format of time it is sufficient with an integer casting and comparison
      if (!(Long.parseLong(currentTime) >= Long.parseLong(notBeforeVal) && Long.parseLong(currentTime) < Long.parseLong(notAfterVal))) {
        System.err.println("Cheque is no longer valid");
        return false;
      }
      // CHECK: the Ethereum address on the attestation matches receivers signing key
      // TODO
      return true;
    }
}
