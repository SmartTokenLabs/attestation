package org.tokenscript.attestation.safeconnect;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.encoders.Base64;
import org.tokenscript.attestation.ObjectDecoder;
import org.tokenscript.attestation.core.DERUtility;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

// Produces up-to-date test material for the JS version
public class ImportExportHelper {
    private static final String rootPath = "build/test-results/";

    public static void produceTestMaterial(SignedEthereumKeyLinkingAttestation att, String description) throws Exception {
        OutputStream out = Files.newOutputStream(Paths.get(rootPath + "signedEthereumKeyLinkingAttestation-" + description + ".txt"));
        String attEnc = Base64.toBase64String(att.getDerEncoding());
        out.write(attEnc.getBytes(StandardCharsets.UTF_8));
        out.close();
    }

    public static SignedEthereumKeyLinkingAttestation loadTestMaterial(ObjectDecoder<SignedOwnershipAttestationInterface> internalDecoder, String description) throws Exception {
        InputStream in = Files.newInputStream(Paths.get(rootPath + "signedEthereumKeyLinkingAttestation-" + description + ".txt"));
        byte[] atteEnc = in.readAllBytes();
        SignedEthereumKeyLinkingAttestationDecoder outerDecoder = new SignedEthereumKeyLinkingAttestationDecoder(internalDecoder);
        SignedEthereumKeyLinkingAttestation att = outerDecoder.decode(Base64.decode(atteEnc));
        in.close();
        return att;
    }

    public static void storeKey(AsymmetricKeyParameter validationKey, String description) throws Exception {
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(validationKey);
        byte[] pub = spki.getEncoded();
        DERUtility.writePEM(pub, "PUBLIC KEY", Paths.get(rootPath + "key-" + description + ".txt"));
    }

    public static AsymmetricKeyParameter loadKey(String description) throws Exception {
        return PublicKeyFactory.createKey
                (DERUtility.restoreBytes(
                        Files.readAllLines(
                                Paths.get(rootPath + "key-" + description + ".txt"))));
    }

}
