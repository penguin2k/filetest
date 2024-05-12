package com.penguin3k.filetest.utils;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKeyStructure;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

public class SM2Util {

    static KeyPair keyPair = createECKeyPair();
    static PublicKey publicKey = keyPair.getPublic();
    static PrivateKey privateKey = keyPair.getPrivate();
    static{
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null){
            //No such provider: BC
            Security.addProvider(new BouncyCastleProvider());
        }
    }
    public static  String getPublicKeyHex(){
        String publicKeyHex = null;
        if (publicKey instanceof BCECPublicKey) {
            //获取65字节非压缩缩的十六进制公钥串(0x04)
            publicKeyHex = Hex.toHexString(((BCECPublicKey) publicKey).getQ().getEncoded(false));
            System.out.println("SM2公钥：" + publicKeyHex);
        }
        return publicKeyHex;
    }
    public static String getPrivateKeyHex() {
        String privateKeyHex = null;
        if (privateKey instanceof BCECPrivateKey) {
            //获取32字节十六进制私钥串
            privateKeyHex = ((BCECPrivateKey)privateKey).getD().toString(16);
            System.out.println("SM2私钥：" + privateKeyHex);
        }
        return privateKeyHex;
    }
    public static KeyPair createECKeyPair() {
        final ECGenParameterSpec sm2Spec = new ECGenParameterSpec("sm2p256v1");

        // 获取一个椭圆曲线类型的密钥对生成器
        final KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
            kpg.initialize(sm2Spec, new SecureRandom());

            return kpg.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
public static  String getkey() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
//    String pemContent = FileUtils.readFileToString(new File("E:\\code\\filetest\\test1.key"), StandardCharsets.UTF_8);
//    System.out.println(pemContent);
//    String base64Content = pemContent.replaceFirst("^-----BEGIN SM2 PRIVATE KEY-----\n", "")
//            .replaceFirst("\n-----END SM2 PRIVATE KEY-----$", "")
//            .replaceAll("\\s", "");
    Security.addProvider(new BouncyCastleProvider());

    String privateKeyFilePath = "E:\\code\\filetest\\test1.key";

    // 读取PEM格式私钥文件
    PrivateKey privateKey = readPrivateKeyFromFile(privateKeyFilePath);
    String privateKeyHex = null;
    if (privateKey instanceof BCECPrivateKey) {
        //获取32字节十六进制私钥串
        privateKeyHex = ((BCECPrivateKey)privateKey).getD().toString(16);
        System.out.println("SM2私钥：" + privateKeyHex);
    }
    return privateKeyHex;
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
    public static String bytesToHexString(byte[] bytes) {
        char[] buf = new char[bytes.length * 2];
        int c = 0;
        for (byte b : bytes) {
            buf[c++] = digits[(b >> 4) & 0x0F];
            buf[c++] = digits[b & 0x0F];
        }
        return new String(buf);
    }

    private final static char[] digits = "0123456789ABCDEF".toCharArray();
    public static  String getpubkey() throws IOException, CertificateException, NoSuchProviderException {        // 1. Open and read the file
        String filePath = "E:\\code\\filetest\\test1.pem";
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

        // 5. Extract the public key
        PublicKey publicKey = certificate.getPublicKey();

        System.out.println("Public Key: " + publicKey);
        String publicKeyHex = null;
        if (publicKey instanceof BCECPublicKey) {
            //获取65字节非压缩缩的十六进制公钥串(0x04)
            publicKeyHex = Hex.toHexString(((BCECPublicKey) publicKey).getQ().getEncoded(false));
            System.out.println("SM2公钥：" + publicKeyHex);
        }
        return publicKeyHex;
    }
    private static String readFileContent(String filePath) throws IOException {
        return new String(Files.readAllBytes(Paths.get(filePath)), StandardCharsets.UTF_8);
    }

    public static  void genprivatekey() throws Exception
    {
//        byte[] privateKeyEncode = privateKey.getEncoded();
//        String privateKeyStr = Base64.getEncoder().encodeToString(privateKeyEncode);
//        System.out.println(privateKeyStr);
//        String privateKeyFileContent = "" +
//                "-----BEGIN SM2 PRIVATE KEY-----\n" +
//                lf(privateKeyStr, 64) +
//                "-----END SM2 PRIVATE KEY-----";
//        FileUtils.write(new File("E:\\code\\filetest\\test1.key"), privateKeyFileContent);
// 创建一个FileOutputStream实例，指向目标文件
        Path path = Paths.get("E:\\code\\filetest\\test1.key");

        // 创建一个PemObject，包含私钥类型和私钥数据
        PemObject pemObject = new PemObject("PRIVATE KEY", privateKey.getEncoded());

        // 创建一个FileWriter，指向目标文件
        try (FileWriter fileWriter = new FileWriter(path.toFile())) {
            // 使用FileWriter创建PemWriter
            try (PemWriter pemWriter = new PemWriter(fileWriter)) {
                // 将私钥PemObject写入PemWriter
                pemWriter.writeObject(pemObject);
            }
        }
    }
    public static void genCertificate() throws Exception
    {
        X500Name subject = generateSubject("CN", "Beijing", "guizhou", "", "", "");
        //下面是PEM格式的证书生成过程
        long currTimestamp = System.currentTimeMillis();
        X500Name issuer = subject;
        X509v3CertificateBuilder x509v3CertificateBuilder = new JcaX509v3CertificateBuilder(
                issuer, BigInteger.valueOf(System.currentTimeMillis()),
                new Date(currTimestamp), new Date(currTimestamp + (long) 365 * 24 * 60 * 60 * 1000),
                subject, publicKey);
        JcaContentSignerBuilder SM3withSM2 = new JcaContentSignerBuilder("SM3withSM2");
        ContentSigner contentSigner = SM3withSM2.build(privateKey);
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
    public static void encrypt( String sourceFilePath, String destinationFilePath) throws CertificateException, IOException, NoSuchProviderException {
        String publicKeyHex = null;
        if (publicKey instanceof BCECPublicKey) {
            //获取65字节非压缩缩的十六进制公钥串(0x04)
            publicKeyHex = Hex.toHexString(((BCECPublicKey) publicKey).getQ().getEncoded(false));
            System.out.println("SM2公钥：" + publicKeyHex);
        }
        encrypt(getECPublicKeyByPublicKeyHex(getpubkey()),sourceFilePath,destinationFilePath);
    }
    public static void  encrypt(BCECPublicKey publicKey,String sourceFilePath, String destinationFilePath)
    {
        SM2Engine.Mode mode = SM2Engine.Mode.C1C3C2;
        ECParameterSpec ecParameterSpec = publicKey.getParameters();
        ECDomainParameters ecDomainParameters = new ECDomainParameters(ecParameterSpec.getCurve(),
                ecParameterSpec.getG(), ecParameterSpec.getN());
        ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(publicKey.getQ(), ecDomainParameters);
        SM2Engine sm2Engine = new SM2Engine(mode);
        sm2Engine.init(true, new ParametersWithRandom(ecPublicKeyParameters, new SecureRandom()));
        // 获取源文件路径
        Path sourcePath = Paths.get(sourceFilePath);
        // 获取目标加密文件路径
        Path destinationPath = Paths.get(destinationFilePath);
        try (InputStream inputStream = Files.newInputStream(sourcePath);
             // 创建输出流，写入加密文件
             OutputStream outputStream = Files.newOutputStream(destinationPath);
             BufferedOutputStream bos= new BufferedOutputStream(outputStream);
             // 创建密码输出流，连接到输出流，并使用密码 cipher 进行加密
            ) {
            byte[] filebyte=FileUtils1.fileToByte(sourceFilePath);
//            // 缓冲区大小
//            byte[] buffer = new byte[4096];
//            int bytesRead;
////            // 读取源文件内容到缓冲区
//            while ((bytesRead =inputStream.read(buffer) ) != -1) {
//                ByteArrayOutputStream encryptedOutputStream = new ByteArrayOutputStream();
//                encryptedOutputStream.write(buffer, 0, bytesRead);
//                byte[] bufferdata=null;
//                 bufferdata =encryptedOutputStream.toByteArray();
//                encryptedOutputStream.close();
//                //outputStream.write(sm2Engine.processBlock(buffer,0,bytesRead));
//                System.out.println("加密数据：" +bufferdata.length);
////                byte[] encryptedData = sm2Engine.processBlock(bufferdata, 0, bytesRead);
////                if (encryptedData != null)
////                    bos.write(encryptedData);
//
//            }
            byte[] encryptedData = sm2Engine.processBlock(filebyte, 0,filebyte.length);
            //encryptedOutputStream.write(sm2Engine.processBlock(new byte[0], 0, 0));
            FileUtils1.byteToFile(encryptedData,destinationFilePath);
            //outputStream.write(encryptedOutputStream.toByteArray());
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
    }
    public static void decrypt( String sourceFilePath, String destinationFilePath) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
        String privateKeyHex = null;
        if (privateKey instanceof BCECPrivateKey) {
            //获取32字节十六进制私钥串
            privateKeyHex = ((BCECPrivateKey) privateKey).getD().toString(16);
            System.out.println("SM2私钥：" + privateKeyHex);
        }
        decrypt(getBCECPrivateKeyByPrivateKeyHex(getkey()),sourceFilePath,destinationFilePath);
    }
    public static void decrypt(BCECPrivateKey privateKey,String sourceFilePath, String destinationFilePath) throws IOException {
        SM2Engine.Mode mode = SM2Engine.Mode.C1C3C2;
        Path sourcePath = Paths.get(sourceFilePath);
        // 获取源加密文件路径
        Path destinationPath = Paths.get(destinationFilePath);
        ECParameterSpec ecParameterSpec = privateKey.getParameters();
        ECDomainParameters ecDomainParameters = new ECDomainParameters(ecParameterSpec.getCurve(),
                ecParameterSpec.getG(), ecParameterSpec.getN());
        ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(privateKey.getD(),
                ecDomainParameters);

        SM2Engine sm2Engine = new SM2Engine(mode);
        sm2Engine.init(false, ecPrivateKeyParameters);
        try (InputStream inputStream = Files.newInputStream(sourcePath);
             // 创建输入流，读取加密文件
             OutputStream outputStream = Files.newOutputStream(destinationPath);
             BufferedOutputStream bos= new BufferedOutputStream(outputStream);){
            //byte[] cipherData=FileUtils.fileToByte(sourceFilePath);
            //byte[] decryptedData = sm2Engine.processBlock(cipherData, 0,cipherData.length);
            //FileUtils.byteToFile(decryptedData,destinationFilePath);
            byte[] buffer = new byte[4096];
            // 缓冲区大小
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                ByteArrayOutputStream encryptedOutputStream = new ByteArrayOutputStream();
                // 读取加密文件内容到缓冲区
                //outputStream.write(sm2Engine.processBlock(buffer,0,bytesRead));
                //byte[] decryptedData = sm2Engine.processBlock(buffer, 0, bytesRead);
                encryptedOutputStream.write(buffer, 0, bytesRead);
                byte [] decryptedbuffer=encryptedOutputStream.toByteArray();
                System.out.println("解密数据长度："+decryptedbuffer.length);
                encryptedOutputStream.close();
                byte[] decryptedData = sm2Engine.processBlock(decryptedbuffer, 0, decryptedbuffer.length);
                if (decryptedData != null)
                    bos.write(decryptedData);;
                // 将解密后的数据写入解密文件
            }
            //outputStream.write(encryptedOutputStream.toByteArray());
        } catch (IOException | InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
    }


    private static X9ECParameters x9ECParameters = GMNamedCurves.getByName("sm2p256v1");

    private static ECParameterSpec ecDomainParameters = new ECParameterSpec(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN());

    public static BCECPublicKey getECPublicKeyByPublicKeyHex(String pubKeyHex) {

        if (pubKeyHex.length() > 128) {
            pubKeyHex = pubKeyHex.substring(pubKeyHex.length() - 128);
        }
        String stringX = pubKeyHex.substring(0, 64);
        String stringY = pubKeyHex.substring(stringX.length());
        BigInteger x = new BigInteger(stringX, 16);
        BigInteger y = new BigInteger(stringY, 16);

        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(x9ECParameters.getCurve().createPoint(x, y), ecDomainParameters);

        return new BCECPublicKey("EC", ecPublicKeySpec, BouncyCastleProvider.CONFIGURATION);
    }

    public static BCECPrivateKey getBCECPrivateKeyByPrivateKeyHex(String privateKeyHex) {
        BigInteger d = new BigInteger(privateKeyHex, 16);
        ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(d, ecDomainParameters);
        return new BCECPrivateKey("EC", ecPrivateKeySpec, BouncyCastleProvider.CONFIGURATION);
    }
}
