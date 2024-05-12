package com.penguin3k.filetest.utils;
import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.SM2;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.*;
import cn.hutool.core.lang.Assert;
import cn.hutool.crypto.SmUtil;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

/**
 * @ClassName SM2Utils
 * @Description SM2算法工具类
 */
public class SM2Utils {

   static KeyPair keyPair = createECKeyPair();
   static PublicKey publicKey = keyPair.getPublic();
   static PrivateKey privateKey = keyPair.getPrivate();
    public static  String getPublicKeyHex(){
        String publicKeyHex = null;
        if (publicKey instanceof BCECPublicKey) {
            //获取65字节非压缩缩的十六进制公钥串(0x04)
            publicKeyHex = Hex.toHexString(((BCECPublicKey) publicKey).getQ().getEncoded(false));
            System.out.println("SM2公钥：" + publicKeyHex);
        }
        return publicKeyHex;
    }
    public static String getPrivateKeyHex(){
        String privateKeyHex = null;
        if (privateKey instanceof BCECPrivateKey) {
            //获取32字节十六进制私钥串
            privateKeyHex = ((BCECPrivateKey) privateKey).getD().toString(16);
            System.out.println("SM2私钥：" + privateKeyHex);
        }
        System.out.println("SM2私钥：" + privateKey);
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

    public static String encrypt( String data) {
        String publicKeyHex = null;
        if (publicKey instanceof BCECPublicKey) {
            //获取65字节非压缩缩的十六进制公钥串(0x04)
            publicKeyHex = Hex.toHexString(((BCECPublicKey) publicKey).getQ().getEncoded(false));
            System.out.println("SM2公钥：" + publicKeyHex);
        }
        return encrypt(getECPublicKeyByPublicKeyHex(publicKeyHex), data, 1);
    }

    public static String encrypt(BCECPublicKey publicKey, String data, int modeType) {
        //加密模式
        SM2Engine.Mode mode = SM2Engine.Mode.C1C3C2;
        if (modeType != 1) {
            mode = SM2Engine.Mode.C1C2C3;
        }
        ECParameterSpec ecParameterSpec = publicKey.getParameters();
        ECDomainParameters ecDomainParameters = new ECDomainParameters(ecParameterSpec.getCurve(),
                ecParameterSpec.getG(), ecParameterSpec.getN());
        ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(publicKey.getQ(), ecDomainParameters);

        SM2Engine sm2Engine = new SM2Engine(mode);

        sm2Engine.init(true, new ParametersWithRandom(ecPublicKeyParameters, new SecureRandom()));
        byte[] arrayOfBytes = null;
        try {
            byte[] in = data.getBytes("utf-8");

            arrayOfBytes = sm2Engine.processBlock(in, 0, in.length);
        } catch (Exception e) {
            System.out.println("SM2加密时出现异常:" + e.getMessage());
            e.printStackTrace();
        }
        return Hex.toHexString(arrayOfBytes);
    }

    public static String decrypt( String cipherData) {
        String privateKeyHex = null;
        if (privateKey instanceof BCECPrivateKey) {
            //获取32字节十六进制私钥串
            privateKeyHex = ((BCECPrivateKey) privateKey).getD().toString(16);
            System.out.println("SM2私钥：" + privateKeyHex);
        }
        return decrypt(getBCECPrivateKeyByPrivateKeyHex(privateKeyHex), cipherData, 1);
    }

    public static String decrypt(BCECPrivateKey privateKey, String cipherData, int modeType) {
        //解密模式
        SM2Engine.Mode mode = SM2Engine.Mode.C1C3C2;
        if (modeType != 1)
            mode = SM2Engine.Mode.C1C2C3;

        byte[] cipherDataByte = Hex.decode(cipherData);
        ECParameterSpec ecParameterSpec = privateKey.getParameters();
        ECDomainParameters ecDomainParameters = new ECDomainParameters(ecParameterSpec.getCurve(),
                ecParameterSpec.getG(), ecParameterSpec.getN());
        ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(privateKey.getD(),
                ecDomainParameters);

        SM2Engine sm2Engine = new SM2Engine(mode);
        sm2Engine.init(false, ecPrivateKeyParameters);
        String result = null;
        try {
            byte[] arrayOfBytes = sm2Engine.processBlock(cipherDataByte, 0, cipherDataByte.length);
            result = new String(arrayOfBytes, "utf-8");
        } catch (Exception e) {
            System.out.println("SM2解密时出现异常" + e.getMessage());
        }
        return result;
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
    //签名
//签名
    public static String sign(String content, BCECPrivateKey privateKey) throws UnsupportedEncodingException {
        //待签名内容转为字节数组
        byte[] message = content.getBytes("utf-8");
        //获取一条SM2曲线参数
        ECParameterSpec ecParameterSpec = privateKey.getParameters();
        //构造domain参数
        ECDomainParameters ecDomainParameters= new ECDomainParameters(ecParameterSpec.getCurve(),
                ecParameterSpec.getG(), ecParameterSpec.getN());
        ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(privateKey.getD(),
                ecDomainParameters);
        //创建签名实例
        SM2Signer sm2Signer = new SM2Signer();
        sm2Signer.init(true,ecPrivateKeyParameters);
        sm2Signer.update(message, 0, message.length);
        try {
            //签名
            byte[] signature = sm2Signer.generateSignature();
            //将签名转为16进制字符串
            System.out.println("SM2签名：" + Hex.toHexString(signature));
            return Hex.toHexString(signature);
        } catch (CryptoException e) {
            throw new RuntimeException(e);
        }
    }

    public static String sign2(String content, String privateKey)   {
        //待签名内容转为字节数组
        byte[] message = content.getBytes();
        //获取一条SM2曲线参数
        X9ECParameters sm2ECParameters = GMNamedCurves.getByName("sm2p256v1");
        //构造domain参数
        ECDomainParameters domainParameters = new ECDomainParameters(sm2ECParameters.getCurve(),
                sm2ECParameters.getG(), sm2ECParameters.getN());

        BigInteger privateKeyD = new BigInteger(privateKey, 16);
        ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(privateKeyD, domainParameters);

        //创建签名实例
        SM2Signer sm2Signer = new SM2Signer();

        //初始化签名实例,带上ID,国密的要求,ID默认值:1234567812345678
        try {
            sm2Signer.init(true, new ParametersWithID(new ParametersWithRandom(privateKeyParameters, SecureRandom.getInstance("SHA1PRNG")), Strings.toByteArray("1234567812345678")));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        sm2Signer.update(message, 0, message.length);
        //生成签名,签名分为两部分r和s,分别对应索引0和1的数组
        byte[] signBytes = new byte[0];
        try {
            signBytes = sm2Signer.generateSignature();
        } catch (CryptoException e) {
            throw new RuntimeException(e);
        }
        //start  bc1.57版本中，signData是纯r+s字符串拼接，如果为了兼容低版本的bc包，则需要加这一句
        //byte[] signData = decodeDERSM2Sign(domainParameters, signBytes);
        //end
        String sign = Hex.toHexString(signBytes);
        return sign;
    }
    public static byte[] encodeSM2SignToDER(byte[] rawSign) throws IOException {
        //要保证大数是正数
        BigInteger r = new BigInteger(1, extractBytes(rawSign, 0, 32));
        BigInteger s = new BigInteger(1, extractBytes(rawSign, 32, 32));
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        return new DERSequence(v).getEncoded(ASN1Encoding.DER);
    }
    private static byte[] extractBytes(byte[] src, int offset, int length) {
        byte[] result = new byte[length];
        System.arraycopy(src, offset, result, 0, result.length);
        return result;
    }
    public static boolean verify2(String content, String publicKey, String sign)  {
        //待签名内容
        byte[] message = Hex.decode(Hex.toHexString(content.getBytes()));
        byte[] signData = Hex.decode(sign);
        try {
            signData = encodeSM2SignToDER(signData);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        // 获取一条SM2曲线参数
        X9ECParameters sm2ECParameters = GMNamedCurves.getByName("sm2p256v1");
        // 构造domain参数
        ECDomainParameters domainParameters = new ECDomainParameters(sm2ECParameters.getCurve(),
                sm2ECParameters.getG(),
                sm2ECParameters.getN());
        //提取公钥点
        ECPoint pukPoint = sm2ECParameters.getCurve().decodePoint(Hex.decode(publicKey));
        // 公钥前面的02或者03表示是压缩公钥，04表示未压缩公钥, 04的时候，可以去掉前面的04
        ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(pukPoint, domainParameters);
        //创建签名实例
        SM2Signer sm2Signer = new SM2Signer();
        ParametersWithID parametersWithID = new ParametersWithID(publicKeyParameters, Strings.toByteArray("1234567812345678"));
        sm2Signer.init(false, parametersWithID);
        sm2Signer.update(message, 0, message.length);
        //验证签名结果
        boolean verify = sm2Signer.verifySignature(signData);
        return verify;
    }
    public static void verify(String content,BCECPublicKey publicKey)
    {
        ECParameterSpec ecParameterSpec = publicKey.getParameters();
        ECDomainParameters ecDomainParameters = new ECDomainParameters(ecParameterSpec.getCurve(),
                ecParameterSpec.getG(), ecParameterSpec.getN());
        ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(publicKey.getQ(), ecDomainParameters);
        SM2Signer sm2Signer = new SM2Signer();
        byte[] cipherDataByte = Hex.decode(content);
        sm2Signer.init(false,ecPublicKeyParameters);
        sm2Signer.update(cipherDataByte,0,cipherDataByte.length);
        System.out.println("SM2验签：" + Hex.toHexString(cipherDataByte));
        System.out.println(sm2Signer.verifySignature(Hex.decode(content)));
        if (sm2Signer.verifySignature(Hex.decode(content))) {
            System.out.println("签名验证通过");
        } else {
            System.out.println("签名验证不通过");
        }
    }
    public static String singandverify( String data) throws UnsupportedEncodingException {

        //sign(data, getBCECPrivateKeyByPrivateKeyHex(getPrivateKeyHex()));
        sign2(data, getPrivateKeyHex());
        verify2(data, getPublicKeyHex(), sign2(data, getPrivateKeyHex()));
        return null;
    }
public static void verify()
{
    // 获取国密曲线
    X9ECParameters gmParameters = GMNamedCurves.getByName("sm2p256v1");
    // 构造Domain参数
    ECDomainParameters gmDomainParameters = new ECDomainParameters(gmParameters.getCurve(),
            gmParameters.getG(), gmParameters.getN());

    try {
        // 从压缩公钥中创建点
        ECPoint sm2Q = gmDomainParameters.getCurve().decodePoint(
                Hex.decode("02a9036e0289d9fa6d566cd0500807e3cba1ce14ba9b58bfbbef00b4b8d502ed72"));

        // 跟私钥一样，在创建ECPublicKeyParameters实例的时候，会去校验点是否符合SM2曲线要求
        ECPublicKeyParameters ecpub = new ECPublicKeyParameters(sm2Q, gmDomainParameters);

        // 默认的摘要算法即是SM3
        SM2Signer sm2Signer = new SM2Signer();
        // 此时默认的userid为1234567812345678
        sm2Signer.init(false, ecpub);
        // 添加待签名的数据
        sm2Signer.update(new byte[]{0x61, 0x62, 0x63}, 0, 3);
        // 校验签名
        boolean verifyResult = sm2Signer.verifySignature(Hex.decodeStrict("edc1431d5871f4f0047775101453f5c7de18ddad9eba7c713fadc23f08e23069b625cf28779efaa432baa3f6682b95534fb6a7fa1c031f2f3778339902f95d66"));
        System.out.println("verifyResult:" + verifyResult);
        //Assert.assertTrue(verifyResult);
    }catch (Exception ex) {
        //Assert.fail(ex.getMessage());
    }
}
//public static void main(String[] args) throws UnsupportedEncodingException {
//    singandverify("1234");
//    String content = "1234";
//    final SM2 sm2 = new SM2(keyPair.getPrivate(), keyPair.getPublic());
//    String sign = sm2.signHex(HexUtil.encodeHexStr(content));
//    System.out.println(sm2.getPrivateKey());
//    System.out.println(sign);
//// true
//    boolean verify = sm2.verifyHex(HexUtil.encodeHexStr(content), sign);
//    System.out.println(verify);

//}
    public static void main(String[] args) {

        /**
         * 公钥加密
         */
        String data = "加密测试";
        String privateKeyHex = null;
        if (privateKey instanceof BCECPrivateKey) {
            //获取32字节十六进制私钥串
            privateKeyHex = ((BCECPrivateKey) privateKey).getD().toString(16);
            System.out.println("SM2私钥：" + privateKeyHex);
        }
        //将十六进制公钥串转换为 BCECPublicKey 公钥对象
        String encryptData = encryptskey(getBCECPrivateKeyByPrivateKeyHex(privateKeyHex), data, 1);
        System.out.println("加密结果：" + encryptData);
        String publicKeyHex = null;
        if (publicKey instanceof BCECPublicKey) {
            //获取65字节非压缩缩的十六进制公钥串(0x04)
            publicKeyHex = Hex.toHexString(((BCECPublicKey) publicKey).getQ().getEncoded(false));
            System.out.println("SM2公钥：" + publicKeyHex);
        }
        /**
         * 私钥解密
         */
        //将十六进制私钥串转换为 BCECPrivateKey 私钥对象
        data =decryptpkey(getECPublicKeyByPublicKeyHex(publicKeyHex), encryptData,1);
        System.out.println("解密结果：" + data);
    }
public static String encryptskey(BCECPrivateKey privateKey, String data, int modeType) {
    //加密模式
    SM2Engine.Mode mode = SM2Engine.Mode.C1C3C2;
    if (modeType != 1) {
        mode = SM2Engine.Mode.C1C2C3;
    }
    ECParameterSpec ecParameterSpec = privateKey.getParameters();
    ECDomainParameters ecDomainParameters = new ECDomainParameters(ecParameterSpec.getCurve(),
            ecParameterSpec.getG(), ecParameterSpec.getN());
    ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(privateKey.getD(),
            ecDomainParameters);

    SM2Engine sm2Engine = new SM2Engine(mode);
    //sm2Engine.init(false, ecPrivateKeyParameters);
    sm2Engine.init(true, new ParametersWithRandom(ecPrivateKeyParameters, new SecureRandom()));
    byte[] arrayOfBytes = null;
    try {
        byte[] in = data.getBytes("utf-8");

        arrayOfBytes = sm2Engine.processBlock(in, 0, in.length);
    } catch (Exception e) {
        System.out.println("SM2加密时出现异常:" + e.getMessage());
        e.printStackTrace();
    }
    return Hex.toHexString(arrayOfBytes);
}
    public static String decryptpkey(BCECPublicKey publicKey, String cipherData, int modeType) {
        //解密模式
        SM2Engine.Mode mode = SM2Engine.Mode.C1C3C2;
        if (modeType != 1)
            mode = SM2Engine.Mode.C1C2C3;

        byte[] cipherDataByte = Hex.decode(cipherData);
        ECParameterSpec ecParameterSpec = publicKey.getParameters();
        ECDomainParameters ecDomainParameters = new ECDomainParameters(ecParameterSpec.getCurve(),
                ecParameterSpec.getG(), ecParameterSpec.getN());
        ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(publicKey.getQ(), ecDomainParameters);

        SM2Engine sm2Engine = new SM2Engine(mode);
        sm2Engine.init(false,ecPublicKeyParameters);
        String result = null;
        try {
            byte[] arrayOfBytes = sm2Engine.processBlock(cipherDataByte, 0, cipherDataByte.length);
            result = new String(arrayOfBytes, "utf-8");
        } catch (Exception e) {
            System.out.println("SM2解密时出现异常" + e.getMessage());
        }
        return result;
    }
}