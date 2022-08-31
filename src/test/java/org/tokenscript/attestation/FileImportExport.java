package org.tokenscript.attestation;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.function.Function;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.encoders.Base64;
import org.tokenscript.attestation.core.DERUtility;

public class FileImportExport {
    private static final String rootPath = "build/test-results/";

    /**
     * Stores a token as a dumb string in file.
     *
     * @param token    The string to store.
     * @param filename The filename to store it under.
     * @throws Exception If something goes wrong.
     */
    public static void storeToken(String token, String filename) throws Exception {
        OutputStream out = Files.newOutputStream(Paths.get(rootPath + filename + ".txt"));
        out.write(token.getBytes(StandardCharsets.UTF_8));
        out.close();
    }

    /**
     * Stores an object as a base64 encoded file.
     *
     * @param obj      The object to store.
     * @param filename The filename to use.
     * @throws Exception If something goes wrong.
     */
    public static void storeMaterial(CheckableObject obj, String filename) throws Exception {
        storeToken(Base64.toBase64String(obj.getDerEncoding()), filename);
    }

    /**
     * Loads a token as a dumb string from a file.
     *
     * @param filename The file where the token is stored.
     * @return The content of @filename as a String.
     * @throws Exception If something goes wrong.
     */
    public static String loadToken(String filename) throws Exception {
        InputStream in = Files.newInputStream(Paths.get(rootPath + filename + ".txt"));
        byte[] tokenEnc = in.readAllBytes();
        in.close();
        return new String(tokenEnc, StandardCharsets.UTF_8);
    }

    /**
     * Load an object stored in a base64 encoded file.
     *
     * @param decoder  A function taking the bytes of the file as input (after base64 decoding) and returns the desired object.
     * @param filename The name of the file to decode.
     * @param <T>      The format of the object to decode.
     * @return The decoded object.
     * @throws Exception If something goes wrong.
     */
    public static <T> T loadMaterial(Function<byte[], T> decoder, String filename) throws Exception {
        InputStream in = Files.newInputStream(Paths.get(rootPath + filename + ".txt"));
        byte[] atteEnc = in.readAllBytes();
        T obj = decoder.apply(Base64.decode(atteEnc));
        in.close();
        return obj;
    }

    /**
     * Load an object stored in a base64 encoded file using a ObjectDecoder
     *
     * @param decoder  The object decoder for the given file.
     * @param filename The name of the file to decode.
     * @param <T>      The format of the object to decode.
     * @return The decoded object.
     * @throws Exception If something goes wrong.
     */
    public static <T extends CheckableObject> T loadMaterial(ObjectDecoder<T> decoder, String filename) throws Exception {
        Function<byte[], T> func = (input) -> {
            try {
                return decoder.decode(input);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        };
        return loadMaterial(func, filename);
    }

    /**
     * Stores a public key as a PEM encoded PKCS compatible SPKI.
     *
     * @param validationKey The key to store
     * @param filename      The file name
     * @throws Exception If something goes wrong.
     */
    public static void storeKey(AsymmetricKeyParameter validationKey, String filename) throws Exception {
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(validationKey);
        byte[] pub = spki.getEncoded();
        DERUtility.writePEM(pub, "PUBLIC KEY", Paths.get(rootPath + filename + ".txt"));
    }

    /**
     * Loads a public key stored as a PEM encoded PKCS compatible SPKI.
     *
     * @param filename The file name
     * @throws Exception If something goes wrong.
     */
    public static AsymmetricKeyParameter loadPubKey(String filename) throws Exception {
        return PublicKeyFactory.createKey
            (DERUtility.restoreBytes(
                Files.readAllLines(
                    Paths.get(rootPath + filename))));
    }

    /**
     * Loads a private ECDSA key stored as a PEM encoded PKCS file.
     *
     * @param filename The file name
     * @throws Exception If something goes wrong.
     */
    public static AsymmetricCipherKeyPair loadPrivKey(String filename) throws Exception {
        return DERUtility.restoreBase64Keys(
            Files.readAllLines(
                Paths.get(rootPath + filename)
            ));
    }
}
