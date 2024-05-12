package com.penguin3k.filetest.utils;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

public class test2 {

    private static final String SM2_STD = "sm2p256v1";
    private static final String SM2_PID = "1234567812345678";

    /**
     * SM2加密算法
     *
     * @param publicKey 公钥
     * @param data      数据
     * @return
     */
    public static String encrypt(String publicKey, String data) throws InvalidCipherTextException {
        // 获取一条SM2曲线参数
        X9ECParameters sm2ECParameters = GMNamedCurves.getByName(SM2_STD);
        // 构造domain参数
        ECDomainParameters domainParameters = new ECDomainParameters(sm2ECParameters.getCurve(),
                sm2ECParameters.getG(), sm2ECParameters.getN());
        //提取公钥点
        ECPoint pukPoint = sm2ECParameters.getCurve()
                .decodePoint(Hex.decode(publicKey));
        // 公钥前面的02或者03表示是压缩公钥，04表示未压缩公钥, 04的时候，可以去掉前面的04
        ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(pukPoint,
                domainParameters);
        SM2Engine sm2Engine = new SM2Engine();
        sm2Engine.init(true, new ParametersWithRandom(publicKeyParameters, new SecureRandom()));
        byte[] arrayOfBytes = null;
        byte[] cipherDataByte = Base64.encode(data.getBytes(StandardCharsets.UTF_8));
        arrayOfBytes = sm2Engine.processBlock(cipherDataByte, 0, cipherDataByte.length);
        return Hex.toHexString(arrayOfBytes);
    }

    /**
     * SM2解密算法
     *
     * @param privateKey 私钥
     * @param data       密文数据
     * @return
     */
    public static String decrypt(String privateKey, String data) throws InvalidCipherTextException {
        //获取一条SM2曲线参数
        X9ECParameters sm2ECParameters = GMNamedCurves.getByName(SM2_STD);
        //构造domain参数
        ECDomainParameters domainParameters = new ECDomainParameters(sm2ECParameters.getCurve(),
                sm2ECParameters.getG(), sm2ECParameters.getN());
        BigInteger privateKeyD = new BigInteger(privateKey, 16);
        ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(privateKeyD,
                domainParameters);
        SM2Engine sm2Engine = new SM2Engine();
        sm2Engine.init(false, privateKeyParameters);
        byte[] arrayOfBytes = null;
        byte[] cipherDataByte = Hex.decode(data);
        arrayOfBytes = sm2Engine.processBlock(cipherDataByte, 0, cipherDataByte.length);
        return new String(Base64.decode(arrayOfBytes), StandardCharsets.UTF_8);
    }
    /**
     * 私钥签名 1.64 模拟 1.57
     * @param privateKey    私钥
     * @param content       待签名内容
     * @return
     */
    public static String sign(String content, String privateKey)   {
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
        byte[] signData = decodeDERSM2Sign(domainParameters, signBytes);
        //end
        String sign = Hex.toHexString(signData);
        return sign;
    }

    /**
     * 私钥签名 DER
     * @param privateKey    私钥
     * @param content       待签名内容
     * @return
     */
    public static String sign4Der(String privateKey, String content) throws CryptoException {
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
        byte[] signBytes = sm2Signer.generateSignature();
        String sign = Hex.toHexString(signBytes);
        return sign;
    }
    /**
     * 验证签名
     * @param publicKey     公钥
     * @param content       待签名内容
     * @param sign          签名值
     * @return
     */
    public static boolean verify(String content, String publicKey, String sign)  {
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
    /**
     * 验证签名
     * @param publicKey     公钥
     * @param content       待签名内容
     * @param sign          签名值
     * @return
     */
    public static boolean verify4Der(String content, String publicKey, String sign)  {
        //待签名内容
        byte[] message = Hex.decode(content);
        byte[] signData = Hex.decode(sign);
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

    /**
     * 把64字节的纯R+S字节流转换成DER编码字节流
     * @param rawSign
     * @return
     * @throws IOException
     */
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


    public static byte[] decodeDERSM2Sign(ECDomainParameters domainParams, byte[] derSign) {
        ASN1Sequence as = DERSequence.getInstance(derSign);
        byte[] rBytes = ((ASN1Integer) as.getObjectAt(0)).getValue().toByteArray();
        byte[] sBytes = ((ASN1Integer) as.getObjectAt(1)).getValue().toByteArray();
        //由于大数的补0规则，所以可能会出现33个字节的情况，要修正回32个字节
        rBytes = fixToCurveLengthBytes(domainParams, rBytes);
        sBytes = fixToCurveLengthBytes(domainParams, sBytes);
        byte[] rawSign = new byte[rBytes.length + sBytes.length];
        System.arraycopy(rBytes, 0, rawSign, 0, rBytes.length);
        System.arraycopy(sBytes, 0, rawSign, rBytes.length, sBytes.length);
        return rawSign;
    }

    private static byte[] fixToCurveLengthBytes(ECDomainParameters domainParams, byte[] src) {
        int curveLen = getCurveLength(domainParams);
        if (src.length == curveLen) {
            return src;
        }
        byte[] result = new byte[curveLen];
        if (src.length > curveLen) {
            System.arraycopy(src, src.length - result.length, result, 0, result.length);
        } else {
            System.arraycopy(src, 0, result, result.length - src.length, src.length);
        }
        return result;
    }

    public static int getCurveLength(ECDomainParameters domainParams) {
        return (domainParams.getCurve().getFieldSize() + 7) / 8;
    }
    /**
     * 将R或者S修正为固定字节数
     *
     * @param rs
     * @return
     */
    private static byte[] modifyRSFixedBytes(byte[] rs) {
        int length = rs.length;
        int fixedLength = 32;
        byte[] result = new byte[fixedLength];
        if (length < 32) {
            System.arraycopy(rs, 0, result, fixedLength - length, length);
        } else {
            System.arraycopy(rs, length - fixedLength, result, 0, fixedLength);
        }
        return result;
    }

    /**
     * 生成SM2公私钥对
     *
     * @return
     */
    public static AsymmetricCipherKeyPair generateKeyPair() throws NoSuchAlgorithmException {
        //获取一条SM2曲线参数
        X9ECParameters sm2ECParameters = GMNamedCurves.getByName(SM2_STD);
        //构造domain参数
        ECDomainParameters domainParameters = new ECDomainParameters(sm2ECParameters.getCurve(),
                sm2ECParameters.getG(), sm2ECParameters.getN());
        //创建密钥生成器
        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
        //初始化生成器,带上随机数
        keyPairGenerator.init(
                new ECKeyGenerationParameters(domainParameters, SecureRandom.getInstance("SHA1PRNG")));
        //生成密钥对
        AsymmetricCipherKeyPair asymmetricCipherKeyPair = keyPairGenerator.generateKeyPair();
        return asymmetricCipherKeyPair;
    }
}

