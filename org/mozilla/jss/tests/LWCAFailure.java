package org.mozilla.jss.tests;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

import org.mozilla.jss.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.netscape.security.util.BigInt;
import org.mozilla.jss.netscape.security.x509.X509Key;

public class LWCAFailure {
    public static X509Key createX509Key(PublicKey publicKey) throws InvalidKeyException {

        if (publicKey instanceof RSAPublicKey) {

            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            return new org.mozilla.jss.netscape.security.provider.RSAPublicKey(
                    new BigInt(rsaPublicKey.getModulus()),
                    new BigInt(rsaPublicKey.getPublicExponent()));

        } else {
            String message = "Unsupported public key: " + publicKey.getClass().getName();
            throw new InvalidKeyException(message);
        }
    }

    public static void createSubCA() throws Exception {
        // Code from: https://github.com/dogtagpki/pki/blob/v10.9/base/ca/src/com/netscape/ca/CertificateAuthority.java#L2852-L2871

        CryptoManager cryptoManager = CryptoManager.getInstance();
        // TODO read PROP_TOKEN_NAME config
        CryptoToken token = cryptoManager.getInternalKeyStorageToken();

        // Key size of sub-CA shall be key size of this CA.
        // If the key is not RSA (e.g. EC) default to 3072 bits.
        //
        // TODO key generation parameters
        KeyPairGenerator gen = token.getKeyPairGenerator(KeyPairAlgorithm.RSA);
        int keySize = 3072;
        // unused: // PublicKey thisPub = mSigningUnit.getPublicKey();
        // unused: // if (thisPub instanceof RSAKey) {
        // unused: //     keySize = ((RSAKey) thisPub).getModulus().bitLength();
        // unused: // }
        gen.initialize(keySize);

        KeyPair keypair = gen.genKeyPair(); // !!Fails here!!
        PublicKey pub = keypair.getPublic();
        X509Key x509key = createX509Key(pub);
        assert x509key != null;
    }

    static class Smasher implements Runnable {
        public void run() {
            try {
                for (int i = 0; i < 100; i++) {
                    LWCAFailure.createSubCA();
                }
            } catch (Exception e) {
                System.err.println(e);
                throw new RuntimeException(e.getMessage(), e);
            }
        }
    }

    public static void main(String[] args) throws Exception {
        int count = 1000;

        System.out.print("Generating keys (serial): ");
        for (int i = 0; i < count; i++) {
            System.out.print(".");
            createSubCA();
        }
        System.out.println(" done!");

        System.out.println("Generating keys (parallel) -- this takes a while!");
        Thread[] threads = new Thread[count];
        for (int i = 0; i < count; i++) {
            Runnable task = new Smasher();
            threads[i] = new Thread(task);
            threads[i].start();
        }

        for (int i = 0; i < count; i++) {
            threads[i].join(0);
        }

        System.out.println("Done!");
    }

}
