package com.penguin3k.filetest.utils;

public class test3 {

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
