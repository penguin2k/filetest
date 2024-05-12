package com.penguin3k.filetest.utils;

import static org.junit.jupiter.api.Assertions.*;

import cn.hutool.core.util.CharsetUtil;
import cn.hutool.core.util.StrUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.Test;

import java.security.*;
import java.util.Base64;

/**
 * @desc: CSR 生成/读取测试类
 * @author: Linwei
 * @created: 2022-06-21 11:02:57
 */
public class CsrUtilTest {


    @Test
    public void testGenerateCsr() throws Exception{
        for(int i=1;i<=10;i++){
            String sn = StrUtil.fillBefore(Integer.toString(i),'0',8);
            System.out.println(sn);
            CsrUtil.generateCsr(true,sn);
            System.out.println("-----------------长长的分割线-------------------------");
        }
        System.out.println(System.currentTimeMillis());
    }

    @Test
    public void readCsrObject() throws Exception{
        String csrStr = "-----BEGIN CERTIFICATE REQUEST-----\n" +
                "MIIC0jCCAboCAQAwgYwxDzANBgNVBAUTBjAwMDAwMDEdMBsGCgmSJomT8ixkARkW\n" +
                "DSouZGVzYXlzdi5jb20xCzAJBgNVBAYTAkNOMRIwEAYDVQQIEwlHdWFuZ2Rvbmcx\n" +
                "CzAJBgNVBAcTAkhaMQ4wDAYDVQQKEwVEZXNheTENMAsGA1UECxMESmF2YTENMAsG\n" +
                "A1UEAxMEVEVTVDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMk4zpqc\n" +
                "2gAKHHmlU182nz5WnM8kps1vzKCWVRO465iMOFePI2a0heW7qQASbriS9qkj9dxi\n" +
                "CBcXlEkq8ba4sDM/VCXZlarVXqjnGy+2KNxgGNuJhM9M9aJD5cS6i6WVbxbhEGMk\n" +
                "1ECW9GffxqUxsBW1t8M0DYTwqVSszvOm9WP+IzT+9kGXHxsImrRm/igwjSplpU2f\n" +
                "TzBXm9oD6nGQh996iHPoij8dGfvEtGenSsfs/SrS9FcG6hemdj5PXvlvR897mUgr\n" +
                "6JEw8E2WMVvvzCcckCfMBmwIgGL+zCOJ4T+oy+vPBJhb7zMcfvKiZ8S/7J2tQuVT\n" +
                "5NUQAQCz5IDDC/UCAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQAJLoUwVqU69V/c\n" +
                "tIHC0R47qrEWmJgU8svs9uUXxR3F++70/yAiajniBI5bPQ+uZwwIPtR34rquDMkh\n" +
                "YWrkJIj5ymyf/w1SIOT/9fCJNrrfgHaTUFFcyVm6+J3LfEFrQsBYgQUrBwGCM7eB\n" +
                "cn+Qsp3LFwspta535K3sBhg+ZKuSKZM94bcFv2MAx8EJ3Z1NmOCPT9nmr5RD38ib\n" +
                "FpMbNtOCTObcoA0a30Pd3nDkBFq1R6AXDuJu3k0ZwhJuW/HQKKfSNpUsE7Tzv5EP\n" +
                "esvx1eTIcM1sKnhNCxBKiLlNX//VEjjXrvybCprLIr5LRli9KmNHA5U6bUdNAEdf\n" +
                "TGRAE7E1\n" +
                "-----END CERTIFICATE REQUEST-----";
        PKCS10CertificationRequest csr = CsrUtil.convertPemToPKCS10CertificationRequest(csrStr);
        System.out.println(Base64.getEncoder().encodeToString(csr.getSubjectPublicKeyInfo().getEncoded()));

        X500Name x500Name = csr.getSubject();
        // 这里就会打印所有的主题
        System.out.println("x500Name is: " + x500Name );
        System.out.println("STATE: " + CsrUtil.getX500Field(BCStyle.STREET, x500Name));
        System.out.println("LOCALE: " + CsrUtil.getX500Field(BCStyle.L, x500Name));
        System.out.println("SERIALNUMBER: " + CsrUtil.getX500Field(BCStyle.SERIALNUMBER, x500Name));
    }

    // 使用BC生成密钥对
    @Test
    public void testGenerateKeyPairs() throws Exception{
        Provider BC = new BouncyCastleProvider();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", BC);
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        String pubKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        String priKey = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        System.out.println(pubKey);
        System.out.println("------------------------");
        System.out.println(priKey);
    }


    /**--------------------------------------------*/
    public static String pubKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx6qNGGJXq9bhszqBLYEW" +
            "MXX4PuVhKkvD/Q4yFM0yQwUCQRF7onfk9KMl54HKf6r4IEygL3Wz/nYN+lG9JYPH" +
            "hz8w23oYNMn5MyWTWztfHLjRr5HfnIgi5skHb3W6Q4SeCjq7IkwBX5b4xIpmcdYP" +
            "pg/Wm4299qc8MxY+fbBRq4tfTsqaYT5eovDNmgLtCeMjVUrmv4qGIs9ewrT9WexD" +
            "qmsjFoDWTVzjVsL73GtVer/2ONdUAb9/YlkCazX2TBaNk4rG4YKxkMFTw8KcHYCG" +
            "JEmbnHpFw+mJijrOI+p8dilGRMxsCWYYRXJQQUjt0wVRrZYrKU094aYnGg76Wj8c" +
            "vQIDAQAB";

    public static String priKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDHqo0YYler1uGz" +
            "OoEtgRYxdfg+5WEqS8P9DjIUzTJDBQJBEXuid+T0oyXngcp/qvggTKAvdbP+dg36" +
            "Ub0lg8eHPzDbehg0yfkzJZNbO18cuNGvkd+ciCLmyQdvdbpDhJ4KOrsiTAFflvjE" +
            "imZx1g+mD9abjb32pzwzFj59sFGri19OypphPl6i8M2aAu0J4yNVSua/ioYiz17C" +
            "tP1Z7EOqayMWgNZNXONWwvvca1V6v/Y411QBv39iWQJrNfZMFo2TisbhgrGQwVPD" +
            "wpwdgIYkSZucekXD6YmKOs4j6nx2KUZEzGwJZhhFclBBSO3TBVGtlispTT3hpica" +
            "DvpaPxy9AgMBAAECggEADeUFKJs/X/VLg5N2Bdqj1rv6PeDsisBMWpcwTljxPyS2" +
            "wXHGrsm1JH5uAYGmEThZSAt3t5XIpClG/mfNx9yMeBGiWW5SXOoT7hvr+JSrIRk4" +
            "zlpSZgGQnDWFJPExDch0JGDDQQxqVA1HhoszEdzu/dlq+oGPT1OCpvN3VHvT/cyi" +
            "VNio17BK8Bj7KrnnwnhGJ5HfJftP8kZU3PVCPSbWfUT6pTdFD1POY0lVBIMZKKDO" +
            "+YGZ5EHs9LDxvaxjH3mmvv4A/R39q8OtPvwg+26JryJ3s/jtfUu7PH0wdMGsuqeL" +
            "GPrVlwZW7KCcImNmpQpWWuR8v/06th4e2ptH6DqwwQKBgQDkEBdI8JkF08Ey0VQR" +
            "+CfzJkT23muvxvOrqGs5On5VKBLaNtqUBq7s0upMJ/NkXJN4SEf+PwKXmhCUAYzG" +
            "LdDELJlGPSoQyJDmt7WAuwZMPGjc0t4NzVQr/vXu+dGauOVS9C+Vm8ny9mw1aqdC" +
            "mM42fTWK3D0jPz2fglEv49YidQKBgQDgH/WSTyox+zxLWsp7n6GhuqQdUTWOYheM" +
            "JkGUFombM/oP8ddNizly16+nx8V/X0BikSPuj3GCCUog4NdIrKe0yMIgx7qz6wcX" +
            "6eIS/VEcvEX/gH2jWaTwtcsWNuNSu8praIdc91MjrsYlco4m19EN8pW1t32Y5L9K" +
            "93UzroI4KQKBgQDGU7fsFk78YkmAh8k0VzlmmcEfbgz3r2v3u16DRfrW0yKR4WHz" +
            "mFxGVqSp1ZQzks4rq6/vyZvXeoMwMqjZLr592srv6gDK16ArA1czu3Cem2oVnsq7" +
            "9fNczzvPtjAw/Nlwail3USMtxl4TlcwefgPWHsyRFTWVkUlljU5M9zUggQKBgAkK" +
            "wQmKEBW8IQ6ZNxoNsqOnt/9Gy3ZXFsQctwCWeC6+xhPmmd0TBNpRQVDvilQ9L4fK" +
            "ezygpN+uKENzTrwr2wg8ITjZVfr0PHEGioxhk+go4FoSgP8aGsFrVCotRLaNxPjY" +
            "Wr2xbLU/09am7H08r750Tv3pzTNh5yXLHftbyv0hAoGAbFL3m9jQb11CSfL4Jp6B" +
            "md9OewV6w05rVwI5+5al1RjcmntEeYAebqOSiNWr4cyJ8fwUMmENbm+oTSpB3JbJ" +
            "79m2BZtHCUCnKdmOkKKOiNCUymNtfzcgUIeMb7rdwjKVjuCxwFK0Bkl9QgcDfQBU" +
            "S03BUmuIHr2ECuINQxek9s8=";

    @Test
    public void testEncryptAndDecrypt() throws Exception {
        String message = "你好,This is a secret message";

        // 加载公钥
        PublicKey publicKey = CsrUtil.loadPublicKey(pubKey);
        System.out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        byte [] encrypt = CsrUtil.encrypt(publicKey, message);
        System.out.println(StrUtil.str(encrypt, CharsetUtil.CHARSET_UTF_8));


        // 加载密钥
        PrivateKey privateKey = CsrUtil.loadPrivateKey(priKey);
        byte[] decrypt = CsrUtil.decrypt(privateKey, encrypt);
        String decryptStr = StrUtil.str(decrypt, CharsetUtil.CHARSET_UTF_8);
        System.out.println(decryptStr);

        //Assert.assertEquals(message, decryptStr);
    }

}
