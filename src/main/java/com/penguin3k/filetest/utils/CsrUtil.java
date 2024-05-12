package com.penguin3k.filetest.utils;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * @desc: Java 代码生成 PKCS#10 规范的证书签名请求 CSR
 * @author: Linwei
 * @created: 2022-06-20 13:26:06
 */
public class CsrUtil {

    private static final Provider BC = new BouncyCastleProvider();

    /**
     * @author: Linwei
     * @created: 2022/6/20 13:30
     * @desc: 生成PKCS#10格式的CSR
     * @param  {@code true}：使用 RSA 加密算法；{@code false}：使用 ECC（SM2）加密算法
     * @return P10证书签名请求 Base64 字符串
     */
    public static String generateCsr(boolean isRsaNotEcc, String sn) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, OperatorCreationException, IOException {
        // 使用 RSA/ECC 算法，生成密钥对（公钥、私钥）
        KeyPairGenerator generator = KeyPairGenerator.getInstance(isRsaNotEcc ? "RSA" : "EC", BC);
        if (isRsaNotEcc) {
            // RSA
            generator.initialize(2048);
        } else {
            // ECC
            generator.initialize(new ECGenParameterSpec("sm2p256v1"));
        }
        KeyPair keyPair = generator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 打印私钥，注意：请务必保存您的私钥
        System.out.println("----------打印私钥");
        String privateKeyStr = getOpensslPemFormatKeyFileContent(privateKey, isRsaNotEcc);
        System.out.println(privateKeyStr);
        System.out.println("----------打印公钥");
        String publicKeyStr = getOpensslPemFormatKeyFileContent(publicKey, isRsaNotEcc);
        System.out.println(publicKeyStr);

        // 按需添加证书主题项，
        // 有些 CSR 不需要我们在主题项中添加各字段,
        // 如 `C=CN, CN=吴仙杰, E=wuxianjiezh@gmail.com, OU=3303..., L=杭州, S=浙江`，
        // 而是通过额外参数提交，故这里我只简单地指定了国家码
        /**
         * CN common name (域名)
         * OU Organizational unit (部门)
         * O  Organization Name （组织）
         * L  Location
         * ST  State
         * C  Country
         * SN device serial number name
         */
        String subjectParam = "CN=*.linwei.com,OU=IT,O=MyCompany,L=Guangzhou,ST=Guangdong," +
                "C=CN," +
                "SERIALNUMBER=" + sn;
        X500Principal subject = new X500Principal(subjectParam);

        // 使用私钥和 SHA256WithRSA/SM3withSM2 算法创建签名者对象
        ContentSigner signer = new JcaContentSignerBuilder(isRsaNotEcc ? "SHA256WithRSA" : "SM3withSM2")
                .setProvider(BC)
                .build(privateKey);

        // 创建 CSR
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, publicKey);
        PKCS10CertificationRequest csr = builder.build(signer);

        // 打印 OpenSSL PEM 格式文件字符串
        System.out.println("----------打印PEM 格式CSR");
        String csrStr = getOpensslPemFormatCsrFileContent(csr);
        System.out.println(csrStr);

        // 以 Base64 字符串形式返回 CSR
        String baseStr = Base64.getEncoder().encodeToString(csr.getEncoded());
        System.out.println("----------打印Base64格式CSR");
        System.out.println(baseStr);
        return baseStr;
    }

    /**
     * 打印 OpenSSL PEM 格式文件字符串的 SSL证书密钥 KEY 文件内容
     *
     * @param privateKey 私钥
     * @param isRsaNotEcc {@code true}：使用 RSA 加密算法；{@code false}：使用 ECC（SM2）加密算法
     * @return 返回私钥字符串
     */
    private static String getOpensslPemFormatKeyFileContent(PrivateKey privateKey, boolean isRsaNotEcc) throws IOException {
        PemObject pem = new PemObject(isRsaNotEcc ? "PRIVATE KEY" : "EC PRIVATE KEY", privateKey.getEncoded());
        StringWriter str = new StringWriter();
        PemWriter pemWriter = new PemWriter(str);
        pemWriter.writeObject(pem);
        pemWriter.close();
        str.close();
        return str.toString();
    }

    private static String getOpensslPemFormatKeyFileContent(PublicKey publicKeyKey, boolean isRsaNotEcc) throws IOException {
        PemObject pem = new PemObject(isRsaNotEcc ? "PUBLIC KEY" : "EC PUBLIC KEY", publicKeyKey.getEncoded());
        StringWriter str = new StringWriter();
        PemWriter pemWriter = new PemWriter(str);
        pemWriter.writeObject(pem);
        pemWriter.close();
        str.close();
        return str.toString();
    }

    /**
     * 打印 OpenSSL PEM 格式文件字符串的 SSL 证书请求 CSR 文件内容
     *
     * @param csr 证书请求对象
     * @return 返回CSR
     */
    private static String getOpensslPemFormatCsrFileContent(PKCS10CertificationRequest csr) throws IOException {
        PemObject pem = new PemObject("CERTIFICATE REQUEST", csr.getEncoded());
        StringWriter str = new StringWriter();
        PemWriter pemWriter = new PemWriter(str);
        pemWriter.writeObject(pem);
        pemWriter.close();
        str.close();

        return str.toString();
    }


    /**
     * @author: Linwei
     * @created: 2022/6/21 10:08
     * @desc: CSR字符串转证书签名请求对象
     * @param csrStr PKCS#10 PEM CSR完整字符串
     */
    public static PKCS10CertificationRequest convertPemToPKCS10CertificationRequest(String csrStr) throws Exception{
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        PKCS10CertificationRequest csr = null;
        ByteArrayInputStream pemStream = null;
        pemStream = new ByteArrayInputStream(csrStr.getBytes("UTF-8"));
        Reader pemReader = new BufferedReader(new InputStreamReader(pemStream));
        PEMParser pemParser = new PEMParser(pemReader);
        Object parsedObj = pemParser.readObject();
        if (parsedObj instanceof PKCS10CertificationRequest) {
            csr = (PKCS10CertificationRequest) parsedObj;
        }
        return csr;
    }
    /**
     * @author: Linwei
     * @created: 2022/6/21 10:10
     * @desc: 读取CSR中的主题信息
     * @param asn1ObjectIdentifier
     * @param x500Name
     */
    public static String getX500Field(String asn1ObjectIdentifier, X500Name x500Name) {
        RDN[] rdnArray = x500Name.getRDNs(new ASN1ObjectIdentifier(asn1ObjectIdentifier));
        String retVal = null;
        for (RDN item : rdnArray) {
            retVal = item.getFirst().getValue().toString();
        }
        return retVal;

    }
    /**
     * @author: Linwei
     * @created: 2022/6/21 10:10
     * @desc: 读取CSR中的主题信息
     * @param asn1ObjectIdentifier
     * @param x500Name
     */
    public static String getX500Field(ASN1ObjectIdentifier asn1ObjectIdentifier, X500Name x500Name) {
        RDN[] rdnArray = x500Name.getRDNs(asn1ObjectIdentifier);
        String retVal = null;
        for (RDN item : rdnArray) {
            retVal = item.getFirst().getValue().toString();
        }
        return retVal;

    }


    /**
     * 从字符串中加载公钥
     *
     */
    public static PublicKey loadPublicKey(String publicKeyStr) throws Exception {
        try {
//			byte[] buffer = StrUtil.bytes(publicKeyStr, CharsetUtil.CHARSET_UTF_8);
            // 注意：先用BASE64解密字符串, 否则会报错误：invalid key format ssl invalid key format
            byte[] buffer = Base64.getDecoder().decode(publicKeyStr);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            return publicKey ;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }
    /**
     * 从字符串中加载私钥
     */
    public static PrivateKey loadPrivateKey(String privateKeyStr) throws Exception {
        try {
            byte[] buffer = Base64.getDecoder().decode(privateKeyStr);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
            return privateKey;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 加密
     */
    public static byte[] encrypt(PublicKey publicKey, String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return cipher.doFinal(message.getBytes("UTF-8"));
    }

    /**
     * 解密
     */
    public static byte[] decrypt(PrivateKey privateKey, byte [] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return cipher.doFinal(encrypted);
    }

}

