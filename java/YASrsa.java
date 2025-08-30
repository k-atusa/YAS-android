package com.example.kutil6_yas;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

// YAS-aes for general
public class YASrsa {
    public String err;
    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;
    private BasicUtil bu;
    public YASrsa() {
        this.bu = new BasicUtil();
    }

    // Generate RSA key (T 4096 F 2048), (public, private)
    public byte[][] Genkey(boolean ext) {
        this.err = "";
        this.publicKey = null;
        this.privateKey = null;
        try {
            // generate key
            int keySize = ext ? 4096 : 2048;
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(keySize, new SecureRandom());
            KeyPair keyPair = keyGen.generateKeyPair();
            this.publicKey = (RSAPublicKey) keyPair.getPublic();
            this.privateKey = (RSAPrivateKey) keyPair.getPrivate();
            return new byte[][]{this.publicKey.getEncoded(), this.privateKey.getEncoded()};
        } catch (Exception e) {
            this.err = e.getMessage();
            return null;
        }
    }

    // Load RSA key, only loads non-null
    public void LoadKey(byte[] publicBytes, byte[] privateBytes) {
        this.err = "";
        this.publicKey = null;
        this.privateKey = null;

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            if (publicBytes != null) {
                X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicBytes);
                this.publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
            }
            if (privateBytes != null) {
                PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateBytes);
                this.privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
            }
        } catch (Exception e) {
            this.err = e.getMessage();
        }
    }

    // RSA encryption with public key
    public byte[] Encrypt(byte[] data) {
        this.err = "";
        try {
            Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA3-256AndMGF1Padding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, this.publicKey, new SecureRandom());
            return cipher.doFinal(data);
        } catch (Exception e) {
            this.err = e.getMessage();
            return null;
        }
    }

    // RSA decryption with private key
    public byte[] Decrypt(byte[] data) {
        this.err = "";
        try {
            Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA3-256AndMGF1Padding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            this.err = e.getMessage();
            return null;
        }
    }

    // RSA sign with private key
    public byte[] Sign(byte[] data) {
        this.err = "";
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA3-256");
            for (int i = 0; i < 10000; i++) { data = digest.digest(data); }
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(this.privateKey, new SecureRandom());
            signature.update(data);
            return signature.sign();
        } catch (Exception e) {
            this.err = e.getMessage();
            return null;
        }
    }

    // RSA verify with public key
    public boolean Verify(byte[] data, byte[] signedData) {
        this.err = "";
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA3-256");
            for (int i = 0; i < 10000; i++) { data = digest.digest(data); }
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(this.publicKey);
            signature.update(data);
            return signature.verify(signedData);
        } catch (Exception e) {
            this.err = e.getMessage();
            return false;
        }
    }
}