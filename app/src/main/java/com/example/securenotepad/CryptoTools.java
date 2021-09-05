package com.example.securenotepad;

import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Objects;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


//import java.security.cert.X509Certificate;

public class CryptoTools {
    private final static String keyPairAlgorythm = "RSA";
    //private final static String cipherAlgorythm = "AES/CBC/PKCS5Padding";
    private final static String cipherAlgorythm = "RSA/ECB/PKCS1Padding";
    private final static String keyStoreAlias = "NoteApp";
    private final static String keyStoreType = "BKS";


    public static String encrypt(String plainText, PublicKey publicKey) {
        String encryptedBase64Text = null;
        try {
            //Creating a Cipher object
            Cipher cipher = Cipher.getInstance(cipherAlgorythm);
            //Initializing a Cipher object
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            encryptedBase64Text = encrypt(plainText, cipher);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return encryptedBase64Text;
    }

    public static String encrypt(String plainText, Cipher cipher) {
        String encryptedBase64Text = null;
        try {
            byte[] plainTextBytes = plainText.getBytes();
            cipher.update(plainTextBytes);
            //Encrypting the data
            byte[] cipherTextBytes = cipher.doFinal();
            encryptedBase64Text = Base64.getEncoder().encodeToString(cipherTextBytes);
        } catch ( BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return encryptedBase64Text;
    }

    public static String encryptBytes(byte[] plainTextBytes, Cipher cipher) {
        String encryptedBase64Text = null;
        try {
            //Encrypting the data
            byte[] cipherTextBytes = cipher.doFinal(plainTextBytes);
            encryptedBase64Text = Base64.getEncoder().encodeToString(cipherTextBytes);
        } catch ( BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return encryptedBase64Text;
    }

    public static String decrypt(String base64Text, PrivateKey privateKey) {
        String decryptedPlainText = null;
        try {
            //Creating a Cipher object
            Cipher cipher = Cipher.getInstance(cipherAlgorythm);
            //Initializing a Cipher object
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            decryptedPlainText = decrypt(base64Text, cipher);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return decryptedPlainText;
    }

    public static String decrypt(String base64Text, Cipher cipher) {
        String decryptedPlainText = null;
        try {
            cipher.update(Base64.getDecoder().decode(base64Text));
            //Decrypting the data
            byte[] cipherTextBytes = cipher.doFinal();
            decryptedPlainText = new String(cipherTextBytes);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return decryptedPlainText;
    }

    public static byte[] decryptBytes(String base64Text, Cipher cipher) {
        byte[] cipherTextBytes = null;
        try {
            //Decrypting the data
            cipherTextBytes = cipher.doFinal(Base64.getDecoder().decode(base64Text));
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return cipherTextBytes;
    }

    private static KeyPair generateKeyPair() {
        KeyPair pair = null;
        try {
            //Creating KeyPair generator object
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(keyPairAlgorythm);
            //Initializing the KeyPairGenerator
            //keyPairGen.initialize(4096);
            //Generate the pair of keys
            pair = keyPairGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return pair;
    }

    public static KeyStore setupKeyStore(String password) {
        KeyStore keyStore = null;
        KeyPair keyPair = generateKeyPair();
        try {
            final X509Certificate cert = SelfSignedCertGenerator.generate(keyPair, "SHA256withRSA", "Mikolaj Co.", 730);
            X509Certificate[] certs = {cert};
            keyStore = KeyStore.getInstance(keyStoreType);
            if(null != password) {
                keyStore.load(null, null);
                keyStore.setKeyEntry(keyStoreAlias, keyPair.getPrivate(), password.toCharArray(), certs);
            } else {
                keyStore.load(null);
                keyStore.setKeyEntry(keyStoreAlias, keyPair.getPrivate().getEncoded(), certs);
            }
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException | OperatorCreationException e) {
            e.printStackTrace();
        }
        return keyStore;
    }

    public static String createKeyStore(String password) {
        String keyStoreBase64 = null;
        KeyStore keyStore = setupKeyStore(password);
        if(null != keyStore) {
            try {
                ByteArrayOutputStream keyStoreOutputStream = new ByteArrayOutputStream();
                keyStore.store(keyStoreOutputStream, password.toCharArray());
                byte[] keyStoreBytes = keyStoreOutputStream.toByteArray();
                keyStoreBase64 = Base64.getEncoder().encodeToString(keyStoreBytes);
            } catch (KeyStoreException | NoSuchAlgorithmException | IOException | CertificateException e) {
                e.printStackTrace();
            }
        }
        return keyStoreBase64;
    }

    private static KeyStore getKeyStore(String keyStoreBase64, String password) {
        KeyStore keyStore = null;
        byte[] keyStoreBytes = Base64.getDecoder().decode(keyStoreBase64);
        try {
            keyStore = KeyStore.getInstance(keyStoreType);
            ByteArrayInputStream  keyStoreInputStream = new ByteArrayInputStream(keyStoreBytes);
            keyStore.load(keyStoreInputStream, password.toCharArray());
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
        return keyStore;
    }

    public static KeyPair getKeyPair(String keyStoreBase64, String password) {
        KeyPair keyPair = null;
        KeyStore keyStore = getKeyStore(keyStoreBase64, password);
        try {
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(CryptoTools.keyStoreAlias, password.toCharArray());
            Certificate cert = keyStore.getCertificate(CryptoTools.keyStoreAlias);
            PublicKey publicKey = cert.getPublicKey();
            keyPair = new KeyPair(publicKey, privateKey);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }
        return keyPair;
    }

    public static String getPasswordHashPBKDF2(String password, String salt) {
        String passwordHash = null;
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA512Digest());
        try {
            gen.init(password.getBytes("UTF-8"), salt.getBytes(), 4096);
            passwordHash = Base64.getEncoder().encodeToString(((KeyParameter) gen.generateDerivedParameters(512)).getKey());
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return passwordHash;
    }

    public static boolean checkPasswordPBKDF2(String passwordHash, String password, String salt) {
        return null != passwordHash && passwordHash.equals(getPasswordHashPBKDF2(password, salt));
    }

    public static String getPasswordBcrypt(String password) {
        final byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return OpenBSDBCrypt.generate("2a", Objects.requireNonNull(password.toCharArray()), salt, 12);

    }

    public static boolean checkPasswordBcrypt(String passwordHash, String password) {
        return OpenBSDBCrypt.checkPassword(passwordHash, password.toCharArray());
    }

    public static void testKeyStore() {
        String message = "Hello, my name is Mikołaj! ***** ***";
        String password = "Admin";
        CryptoTools cryptoTools = new CryptoTools();
        String keyStoreBase64 = cryptoTools.createKeyStore(password);

        KeyPair keyPair = cryptoTools.getKeyPair(keyStoreBase64, password);
        String encrypted = cryptoTools.encrypt(message, keyPair.getPublic());
        System.out.println(encrypted);
        String decrypted = cryptoTools.decrypt(encrypted, keyPair.getPrivate());
        System.out.println("wiadomosc: " + decrypted);
    }

    public static void testPasswordHashPBKDF2() {
        CryptoTools cryptoTools = new CryptoTools();
        String password = "Admin";
        String salt = "abc123!@#";
        String hashPassword = cryptoTools.getPasswordHashPBKDF2(password, salt);
        if (cryptoTools.checkPasswordPBKDF2(hashPassword, "Admin", salt)) {
            System.out.println("hasło poprawne, hash: " + hashPassword);
        } else System.out.println("hasło niepoprawne, hash: " + hashPassword);
    }

    public static void testPasswordHashBcrypt() {
        CryptoTools cryptoTools = new CryptoTools();
        String password = "Admin";
        String hashPassword = cryptoTools.getPasswordBcrypt(password);
        if (cryptoTools.checkPasswordBcrypt(hashPassword, "Admin")) {
            System.out.println("hasło poprawne, hash: " + hashPassword);
        } else System.out.println("hasło niepoprawne, hash: " + hashPassword);
    }

    public static void main(String[] args) {
        testKeyStore();
        //testPasswordHashBcrypt();
    }
}