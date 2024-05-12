package com.penguin3k.filetest.utils;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
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

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;

public class test {
    /**
     * 生成自签名的PEM格式的证书和私钥文件
     */
    public static void main(String[] args) throws OperatorCreationException, IOException {
        //生成主题信息
        X500Name subject = generateSubject("CN", "Beijing", "Beijing", "penguin", "", "www.test.com");
        //生成RSA密钥对
        KeyPair keyPair = generateRsaKeyPair(2048);
        assert keyPair != null;
        PublicKey aPublic = keyPair.getPublic();
        PrivateKey aPrivate = keyPair.getPrivate();
        //下面是私钥key生成的过程
        byte[] privateKeyEncode = aPrivate.getEncoded();
        String privateKeyStr = Base64.getEncoder().encodeToString(privateKeyEncode);
        String privateKeyFileContent = "" +
                "-----BEGIN RSA PRIVATE KEY-----\n" +
                lf(privateKeyStr, 64) +
                "-----END RSA PRIVATE KEY-----";
        FileUtils.write(new File("E:\\code\\filetest\\test1.key"), privateKeyFileContent,
                StandardCharsets.UTF_8);
        //下面是PEM格式的证书生成过程
        long currTimestamp = System.currentTimeMillis();
        X500Name issuer = subject;
        X509v3CertificateBuilder x509v3CertificateBuilder = new JcaX509v3CertificateBuilder(
                issuer, BigInteger.valueOf(System.currentTimeMillis()),
                new Date(currTimestamp), new Date(currTimestamp + (long) 365 * 24 * 60 * 60 * 1000),
                subject, aPublic);
        JcaContentSignerBuilder sha256WITHRSA = new JcaContentSignerBuilder("SHA256WITHRSA");
        ContentSigner contentSigner = sha256WITHRSA.build(aPrivate);
        X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder.build(contentSigner);
        Certificate certificate = x509CertificateHolder.toASN1Structure();
        byte[] encoded = certificate.getEncoded();
        String certStr = Base64.getEncoder().encodeToString(encoded);
        String certFileContent = "" +
                "-----BEGIN CERTIFICATE-----\n" +
                lf(certStr, 64) +
                "-----END CERTIFICATE-----";
        FileUtils.write(new File("E:\\code\\filetest\\test1.pem"), certFileContent,
                StandardCharsets.UTF_8);
//        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
//                .setProvider(new BouncyCastleProvider())
//                .build(aPrivate);
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject,aPublic);
        PKCS10CertificationRequest csr = builder.build(contentSigner);
        System.out.println("----------打印PEM 格式CSR");
        String csrStr = getOpensslPemFormatCsrFileContent(csr);
        FileUtils.write(new File("E:\\code\\filetest\\csr.pem"), csrStr,
                StandardCharsets.UTF_8);
        System.out.println(csrStr);
    }

    private static PublicKey toPublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(subjectPublicKeyInfo.getAlgorithm().getAlgorithm().getId(), "BC");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded());
        return keyFactory.generatePublic(keySpec);
    }
    public static  void  signand() throws Exception {
        // 读取CSR文件
        String csrFilePath = "E:\\code\\filetest\\csr.pem";
        String csrBytes = Files.readString(Paths.get(csrFilePath));
        PKCS10CertificationRequest csr = convertPemToPKCS10CertificationRequest(csrBytes);
        PublicKey spublicKey=toPublicKey(csr.getSubjectPublicKeyInfo());
        System.out.println(Base64.getEncoder().encodeToString(csr.getSubjectPublicKeyInfo().getEncoded()));
        // 创建CA的密钥对（实际应用中，CA的密钥应该是安全存储的）
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);
        KeyPair caKeyPair = keyGen.generateKeyPair();
        PrivateKey caPrivateKey = caKeyPair.getPrivate();
        long currTimestamp = System.currentTimeMillis();
        X500Name subject = csr.getSubject();
        X500Name issuer=generateSubject("CN", "Beijing", "Beijing", "penguin", "", "www.test.com");

        X509v3CertificateBuilder x509v3CertificateBuilder = new JcaX509v3CertificateBuilder(
                issuer, BigInteger.valueOf(System.currentTimeMillis()),
                new Date(currTimestamp), new Date(currTimestamp + (long) 365 * 24 * 60 * 60 * 1000),
                subject,spublicKey);
        JcaContentSignerBuilder sha256WITHRSA = new JcaContentSignerBuilder("SHA256WITHRSA");
        ContentSigner contentSigner = sha256WITHRSA.build(caPrivateKey);
        X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder.build(contentSigner);
        Certificate certificate = x509CertificateHolder.toASN1Structure();
        byte[] encoded = certificate.getEncoded();
        String certStr = Base64.getEncoder().encodeToString(encoded);
        String certFileContent = "" +
                "-----BEGIN CERTIFICATE-----\n" +
                lf(certStr, 64) +
                "-----END CERTIFICATE-----";
        FileUtils.write(new File("E:\\code\\filetest\\test2.pem"), certFileContent,
                StandardCharsets.UTF_8);
        // 创建证书生成器
    }
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
    public static String getX500Field(ASN1ObjectIdentifier asn1ObjectIdentifier, X500Name x500Name) {
        RDN[] rdnArray = x500Name.getRDNs(asn1ObjectIdentifier);
        String retVal = null;
        for (RDN item : rdnArray) {
            retVal = item.getFirst().getValue().toString();
        }
        return retVal;

    }
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
     * 生成Subject信息
     *
     * @param C  Country Name (国家代号),eg: CN
     * @param ST State or Province Name (洲或者省份),eg: Beijing
     * @param L  Locality Name (城市名),eg: Beijing
     * @param O  Organization Name (可以是公司名称),eg: 北京创新乐知网络技术有限公司
     * @param OU Organizational Unit Name (可以是单位部门名称)
     * @param CN Common Name (服务器ip或者域名),eg: 192.168.30.71 or www.baidu.com
     * @return X500Name Subject
     */
    public static X500Name generateSubject(String C, String ST, String L,
                                           String O, String OU, String CN) {
        X500NameBuilder x500NameBuilder = new X500NameBuilder();
        x500NameBuilder.addRDN(BCStyle.C, C);
        x500NameBuilder.addRDN(BCStyle.ST, ST);
        x500NameBuilder.addRDN(BCStyle.L, L);
        x500NameBuilder.addRDN(BCStyle.O, O);
        x500NameBuilder.addRDN(BCStyle.OU, OU);
        x500NameBuilder.addRDN(BCStyle.CN, CN);
        return x500NameBuilder.build();
    }

    public static KeyPair generateRsaKeyPair(int keySize) {
        try {
            KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
            rsa.initialize(keySize);
            return rsa.generateKeyPair();
        } catch (NoSuchAlgorithmException ignore) {
        }
        return null;
    }

    public static String lf(String str, int lineLength) {
        assert str != null;
        assert lineLength > 0;
        StringBuilder sb = new StringBuilder();
        char[] chars = str.toCharArray();
        int n = 0;
        for (char aChar : chars) {
            sb.append(aChar);
            n++;
            if (n == lineLength) {
                n = 0;
                sb.append("\n");
            }
        }
        if (n != 0)
            sb.append("\n");
        return sb.toString();
    }
    public static X509Certificate getcertificate(String filePath) throws CertificateException, NoSuchProviderException, IOException, InvalidNameException {
        String pemContent = readFileContent(filePath);
        Security.addProvider(new BouncyCastleProvider());
        // 2. Parse PEM format
        String base64CertData =pemContent.replaceFirst("^-----BEGIN CERTIFICATE-----\n", "")
                .replaceFirst("\n-----END CERTIFICATE-----$", "")
                .replaceAll("\\s", "");;

        // 3. Decode Base64
        byte[] certBytes = Base64.getDecoder().decode(base64CertData);

        // 4. Load the certificate
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
        //System.out.println("Certificate: " + certificate);
        System.out.println(Base64.getEncoder().encodeToString(certificate.getPublicKey().getEncoded()));
       // System.out.println("证书"+certificate);
        Date expirationDate = certificate.getNotAfter();
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
        String formattedExpirationDate = sdf.format(expirationDate);
        System.out.println("证书过期时间: " + formattedExpirationDate);

        String subjectDN = certificate.getSubjectX500Principal().toString();
        System.out.println("证书颁发者: " + subjectDN);
//// 获取证书主体的DN (Distinguished Name)
//        X500Principal subjectDN = certificate.getSubjectX500Principal();
//
//// 将DN转换为可读的名称字符串
//        String subjectDNString = subjectDN.getName();
// 将DN字符串转换为LdapName对象以便解析
        LdapName ldapName = new LdapName(subjectDN);
        String name = "";
//
// 遍历RDN（Relative Distinguished Names），查找'O'属性
        for (Rdn rdn : ldapName.getRdns()) {
            if ("O".equalsIgnoreCase(rdn.getType())) {
                String organizationName = (String) rdn.getValue();
                //System.out.println("证书主体的组织名称: " + organizationName);
                name=organizationName;
                break; // 找到后退出循环
            }
        }

        System.out.println("证书主体的组织名称: " + name);
//// 提取主体的组织名称 (O=OrganizationName)
//        int start = subjectDNString.indexOf("O=") + 2; // 跳过'O='
//        int end = subjectDNString.indexOf(",", start); // 查找下一个逗号的位置以确定O值的结束
//        if (end == -1) { // 如果没有找到逗号，说明O是DN的最后一部分
//            end = subjectDNString.length();
//        }
//
//// 获取并输出组织名称
//        String organizationName = subjectDNString.substring(start, end).trim();
        //System.out.println("证书主体的组织名称: " + organizationName);
        return certificate;
    }
    private static String readFileContent(String filePath) throws IOException {
        return new String(Files.readAllBytes(Paths.get(filePath)), StandardCharsets.UTF_8);
    }
}
