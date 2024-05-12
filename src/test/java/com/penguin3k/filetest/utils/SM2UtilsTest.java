package com.penguin3k.filetest.utils;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.io.UnsupportedEncodingException;

import static org.junit.jupiter.api.Assertions.*;

class SM2UtilsTest {

    @Test
    void sign2() throws UnsupportedEncodingException {
        SM2Utils.singandverify("1234");
    }

    @Test
    void verify() {
        System.out.println(SM2Utils.decrypt(SM2Utils.encrypt("1231231412")));
        //SM2Utils.decrypt(SM2Utils.encrypt("1231231412"));
    }
    @Test
    public void testVerifyWithCustomUserId() {
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

            // 自定义userid
            ParametersWithID customIdParameters = new ParametersWithID(ecpub,
                    Hex.decodeStrict("31323334353637383837363534333231"));

            // 默认的摘要算法即是SM3
            SM2Signer sm2Signer = new SM2Signer();
            // 此时的userid为1234567887654321
            sm2Signer.init(false, customIdParameters);
            // 添加待签名的数据
            sm2Signer.update(new byte[]{0x61, 0x62, 0x63}, 0, 3);
            // 校验签名
            boolean verifyResult = sm2Signer.verifySignature(Hex.decodeStrict("732286b4258a1bb7cfb4c8b4156f39661bf1785b48531d521e38b5cb1237c90517e8df1a8c7530c8d813af0c4da784b0e69c125fdef9128b6ff3e0b9242ac850"));

            System.out.println(verifyResult);
        }catch (Exception ex) {

        }
    }
}