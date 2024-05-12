package com.penguin3k.filetest.utils;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import java.security.*;

public class ECCEncryptionExample {
    public static void main(String[] args) throws Exception {
        // 添加Bouncy Castle作为加密提供程序
        Security.addProvider(new BouncyCastleProvider());

        // 选择椭圆曲线参数
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");

        // 生成密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(ecSpec, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // 获取公钥和私钥
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // 明文
        String plainText = "Hello, World!";

        // 加密
        byte[] encryptedBytes = encrypt(plainText, publicKey);
        String encryptedText = Base64.toBase64String(encryptedBytes);
        System.out.println("Encrypted Text: " + encryptedText);

        // 解密
        byte[] decryptedBytes = decrypt(encryptedBytes, privateKey);
        String decryptedText = new String(decryptedBytes);
        System.out.println("Decrypted Text: " + decryptedText);

        byte[] encryptedBytes2 = encryptskey(plainText, privateKey);
        String decryptedText2 =  Base64.toBase64String(encryptedBytes2);
        System.out.println("Decrypted Text: " + decryptedText2);

        byte[] decryptedBytes2 = decryptpkey(encryptedBytes2, publicKey);
        String decryptedText3 = new String(decryptedBytes2);
        System.out.println("Decrypted Text: " + decryptedText3);
    }

    public static byte[] encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plainText.getBytes());
    }

    public static byte[] decrypt(byte[] encryptedBytes, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedBytes);
    }
    public static byte[] encryptskey(String plainText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(plainText.getBytes());
    }

    public static byte[] decryptpkey(byte[] encryptedBytes, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(encryptedBytes);
    }
}