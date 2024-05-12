package com.penguin3k.filetest.utils;
import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

// 用户类
class Person {
    public final String name; // 姓名

    // 密钥
    public PublicKey publicKey; // 公钥
    private PrivateKey privateKey; // 私钥
    private byte[] secretKey; // 本地秘钥(共享密钥)
    // 构造方法
    public Person(String name) {
        this.name = name;
    }
    // 生成本地KeyPair:(公钥+私钥)
    public void generateKeyPair() {
        try {
            // 创建DH算法的“秘钥对”生成器
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("DH");
            kpGen.initialize(512);

            // 生成一个"密钥对"
            KeyPair kp = kpGen.generateKeyPair();
            this.privateKey = kp.getPrivate(); // 私钥
            this.publicKey = kp.getPublic(); // 公钥

        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    // 按照 "对方的公钥" => 生成"共享密钥"
    public void generateSecretKey(byte[] receivedPubKeyBytes) {
        try {
            // 从byte[]恢复PublicKey:
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receivedPubKeyBytes);

            // 根据DH算法获取KeyFactory
            KeyFactory kf = KeyFactory.getInstance("DH");
            // 通过KeyFactory创建公钥
            PublicKey receivedPublicKey = kf.generatePublic(keySpec);

            // 创建秘钥协议对象(用于秘钥协商)
            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(this.privateKey); // 初始化"自己的PrivateKey"
            keyAgreement.doPhase(receivedPublicKey, true); // 根据"对方的PublicKey"

            // 生成SecretKey本地密钥(共享公钥)
            this.secretKey = keyAgreement.generateSecret();

        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }
    public void printKeys() {
        System.out.printf("Name: %s\n", this.name);
        System.out.printf("Private key: %x\n", new BigInteger(1,                                                                             this.privateKey.getEncoded()));
        System.out.printf("Public key: %x\n", new BigInteger(1, this.publicKey.getEncoded()));
        System.out.printf("Secret key: %x\n", new BigInteger(1, this.secretKey));
    }
    public class Main {
        public static void main(String[] args) {
            // Bob和Alice:
            Person bob = new Person("Bob");
            Person alice = new Person("Alice");

            // 各自生成KeyPair: 公钥+私钥
            bob.generateKeyPair();
            alice.generateKeyPair();

            // 双方交换各自的PublicKey(公钥):
            // Bob根据Alice的PublicKey生成自己的本地密钥(共享公钥):
            bob.generateSecretKey(alice.publicKey.getEncoded());

            // Alice根据Bob的PublicKey生成自己的本地密钥(共享公钥):
            alice.generateSecretKey(bob.publicKey.getEncoded());

            // 检查双方的本地密钥是否相同:
            bob.printKeys();
            alice.printKeys();

            // 双方的SecretKey相同，后续通信将使用SecretKey作为密钥进行AES加解密...
        }
    }
}
