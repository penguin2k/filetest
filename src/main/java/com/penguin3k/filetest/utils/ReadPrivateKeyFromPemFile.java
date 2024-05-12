package com.penguin3k.filetest.utils;

import java.io.FileReader;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.util.io.pem.PemObject;

public class ReadPrivateKeyFromPemFile {
    public static void main(String[] args) throws Exception {
        // 添加Bouncy Castle作为JCE提供者（如果尚未添加）
        Security.addProvider(new BouncyCastleProvider());

        String privateKeyFilePath = "E:\\code\\filetest\\test1.key";

        // 读取PEM格式私钥文件
        PrivateKey privateKey = readPrivateKeyFromFile(privateKeyFilePath);
        byte[] privateKeyBytes = privateKey.getEncoded();
        System.out.println(Base64.getEncoder().encodeToString(privateKeyBytes));
        System.out.println("Private Key loaded successfully.");
    }
    public static PrivateKey readPrivateKeyFromFile(String privateKeyFilePath) throws IOException {
        try (PEMParser pemParser = new PEMParser(new FileReader(privateKeyFilePath))) {
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);

            Object pemObject = pemParser.readObject();

            if (pemObject instanceof PrivateKeyInfo) {
                return converter.getPrivateKey((PrivateKeyInfo) pemObject);
            }  else {
                throw new IllegalArgumentException("Unexpected object type: " + pemObject.getClass());
            }
        }
    }
}