//package com.penguin3k.filetest.utils;
//
//import io.micrometer.common.util.StringUtils;
//
//import javax.crypto.Cipher;
//import javax.crypto.NoSuchPaddingException;
//import java.io.FileInputStream;
//import java.security.*;
//import java.util.HashMap;
//import java.util.Map;
//
//public class RsaEncryptUtil{
//    public static final String PUBLIC_KEY="publicKey";
//    public static final String PRIVATE_KEY="privateKey";
//    private static final String KEY_STORE = "JKS";
//
//    private static final int MAX_ENCRYPT_LENGTH = 117;
//    private static final int MAX_DECRYPT_LENGTH = 128;
//
//    /**
//     * 随机生成RAS公钥与私钥字符串，直接返回
//     */
//    public static Map<String, String> getKeys() {
//        KeyPairGenerator keyPairGen;
//        try {
//            keyPairGen = KeyPairGenerator.getInstance("RSA");
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//            throw new RSAException("RSA获取钥匙对失败", e);
//        }
//
//        // 初始化密钥对生成器，密钥大小为96-1024位
//        keyPairGen.initialize(1024,new SecureRandom());
//        // 生成一个密钥对，保存在keyPair中
//        KeyPair keyPair = keyPairGen.generateKeyPair();
//        Map<String,String> keyMap = new HashMap<>();
//        keyMap.put(PUBLIC_KEY, RSACryptUtil.base64ToStr(keyPair.getPublic().getEncoded()));
//        keyMap.put(PRIVATE_KEY, RSACryptUtil.base64ToStr(keyPair.getPrivate().getEncoded()));
//
//        return keyMap;
//    }
//
//    /**
//     * 获得KeyStore
//     *
//     * @param keyStorePath
//     * @param password
//     */
//    private static KeyStore getKeyStore(String keyStorePath, String password) throws Exception {
//        FileInputStream is = new FileInputStream(keyStorePath);
//        KeyStore ks = KeyStore.getInstance(KEY_STORE);
//        ks.load(is, password.toCharArray());
//        is.close();
//        return ks;
//    }
//
//    /**
//     * 由KeyStore获得私钥
//     *
//     * @param keyStorePath  KeyStore路径
//     * @param alias         别名
//     * @param storePass     KeyStore访问密码
//     * @param keyPass       私钥的钥匙密码
//     */
//    private static PrivateKey loadPrivateKey(String keyStorePath, String alias, String storePass, String keyPass) throws Exception {
//        KeyStore ks = getKeyStore(keyStorePath, storePass);
//        PrivateKey key = (PrivateKey) ks.getKey(alias, keyPass.toCharArray());
//        return key;
//    }
//
//    /**
//     * 由Certificate获得公钥
//     *
//     * @param keyStorePath  KeyStore路径
//     * @param alias         别名
//     * @param storePass     KeyStore访问密码
//     */
//    private static PublicKey loadPublicKey(String keyStorePath, String alias, String storePass) throws Exception {
//        KeyStore ks = getKeyStore(keyStorePath, storePass);
//        PublicKey key = ks.getCertificate(alias).getPublicKey();
//        return key;
//    }
//
//
//    /**
//     * 公钥加密
//     *
//     * @param publicKey     公钥
//     * @param content       明文数据
//     */
//    public static String encryptByPublic(String publicKey, String content){
//        if (StringUtils.isEmpty(publicKey)) {
//            throw new RSAException("加密公钥为空, 请设置");
//        }
//        if(StringUtils.isEmpty(content)){
//            throw new RSAException("加密明文为空, 请设置");
//        }
//        Cipher cipher;
//        StringBuilder result = new StringBuilder();
//        try {
//            // 使用默认RSA
//            cipher = Cipher.getInstance("RSA");
//            cipher.init(Cipher.ENCRYPT_MODE, RSACryptUtil.loadPublicKey(publicKey));
//            byte[] bytes = content.getBytes();
//            for (int i = 0; i < bytes.length; i += MAX_ENCRYPT_LENGTH) {
//                byte[] subarray = ArrayUtils.subarray(bytes, i, i + MAX_ENCRYPT_LENGTH);
//                if(subarray != null && subarray.length > 0){
//                    byte[] doFinal = cipher.doFinal(subarray);
//                    result.append(RSACryptUtil.base64ToStr(doFinal));
//                }
//            }
//            return result.toString();
//        } catch (NoSuchAlgorithmException e) {
//            throw new RSAException("无此加密算法",e);
//        } catch (NoSuchPaddingException e) {
//            e.printStackTrace();
//            return null;
//        } catch (InvalidKeyException e) {
//            throw new RSAException("加密公钥非法,请检查",e);
//        } catch (IllegalBlockSizeException e) {
//            throw new RSAException("明文长度非法",e);
//        } catch (BadPaddingException e) {
//            throw new RSAException("明文数据已损坏",e);
//        } catch (Exception e) {
//            throw new RSAException("未知错误",e);
//        }
//    }
//
//    /**
//     * 私钥解密
//     *
//     * @param privateKey    私钥
//     * @param content       密文数据
//     */
//    public static String decryptByPrivate(String privateKey, String content){
//        if (StringUtils.isEmpty(privateKey)) {
//            throw new RSAException("解密私钥为空, 请设置");
//        }
//        if(StringUtils.isEmpty(content)){
//            throw new RSAException("解密密文为空, 请设置");
//        }
//        if(content.length() < 4){
//            throw new RSAException("解密密文有误：" + content);
//        }
//        Cipher cipher;
//        StringBuilder result = new StringBuilder();
//        try {
//            // 使用默认RSA
//            cipher = Cipher.getInstance("RSA");
//            cipher.init(Cipher.DECRYPT_MODE, RSACryptUtil.loadPrivateKey(privateKey));
//            byte[] bytes = RSACryptUtil.strToBase64(content);
//            for (int i = 0; i < bytes.length; i += MAX_DECRYPT_LENGTH) {
//                byte[] subarray = ArrayUtils.subarray(bytes, i, i + MAX_DECRYPT_LENGTH);
//                if(subarray != null && subarray.length > 0){
//                    byte[] doFinal = cipher.doFinal(subarray);
//                    result.append(new String(doFinal));
//                }
//            }
//            return result.toString();
//        } catch (NoSuchAlgorithmException e) {
//            throw new RSAException("无此解密算法",e);
//        } catch (NoSuchPaddingException e) {
//            e.printStackTrace();
//            return null;
//        } catch (InvalidKeyException e) {
//            throw new RSAException("解密私钥非法,请检查");
//        } catch (IllegalBlockSizeException e) {
//            throw new RSAException("密文长度非法",e);
//        } catch (BadPaddingException e) {
//            throw new RSAException("密文数据已损坏",e);
//        } catch (Exception e) {
//            e.printStackTrace();
//            throw new RSAException("未知错误",e);
//        }
//    }
//
//
//    /**
//     * 私钥加密
//     *
//     * @param privateKey    私钥
//     * @param content       明文数据
//     */
//    public static String encryptByPrivate(String privateKey,String content){
//        if (StringUtils.isEmpty(privateKey)) {
//            throw new RSAException("加密私钥为空, 请设置");
//        }
//        if(StringUtils.isEmpty(content)){
//            throw new RSAException("加密明文为空, 请设置");
//        }
//        Cipher cipher;
//        StringBuilder result = new StringBuilder();
//        try {
//            // 使用默认RSA
//            cipher = Cipher.getInstance("RSA");
//            cipher.init(Cipher.ENCRYPT_MODE, RSACryptUtil.loadPrivateKey(privateKey));
//            byte[] bytes = content.getBytes();
//            for (int i = 0; i < bytes.length; i += MAX_ENCRYPT_LENGTH) {
//                byte[] subarray = ArrayUtils.subarray(bytes, i, i + MAX_ENCRYPT_LENGTH);
//                if(subarray != null && subarray.length > 0){
//                    byte[] doFinal = cipher.doFinal(subarray);
//                    result.append(RSACryptUtil.base64ToStr(doFinal));
//                }
//            }
//            return result.toString();
//        }catch (NoSuchAlgorithmException e) {
//            throw new RSAException("无此加密算法",e);
//        } catch (NoSuchPaddingException e) {
//            e.printStackTrace();
//            return null;
//        } catch (InvalidKeyException e) {
//            throw new RSAException("加密私钥非法,请检查",e);
//        } catch (IllegalBlockSizeException e) {
//            throw new RSAException("明文长度非法",e);
//        } catch (BadPaddingException e) {
//            throw new RSAException("明文数据已损坏",e);
//        }
//    }
//
//
//    /**
//     * 公钥解密
//     *
//     * @param publicKey     公钥
//     * @param content       密文数据
//     */
//    public static String decryptByPublic(String publicKey, String content){
//        if (StringUtils.isEmpty(publicKey)) {
//            throw new RSAException("解密公钥为空, 请设置");
//        }
//        if(StringUtils.isEmpty(content)){
//            throw new RSAException("解密密文为空, 请设置");
//        }
//        if(content.length() < 4){
//            throw new RSAException("解密密文有误：" + content);
//        }
//        Cipher cipher;
//        StringBuilder result = new StringBuilder();
//        try {
//            // 使用默认RSA
//            cipher = Cipher.getInstance("RSA");
//            cipher.init(Cipher.DECRYPT_MODE, RSACryptUtil.loadPublicKey(publicKey));
//            byte[] bytes = RSACryptUtil.strToBase64(content);
//            for (int i = 0; i < bytes.length; i += MAX_DECRYPT_LENGTH) {
//                byte[] subarray = ArrayUtils.subarray(bytes, i, i + MAX_DECRYPT_LENGTH);
//                if(subarray != null && subarray.length > 0){
//                    byte[] doFinal = cipher.doFinal(subarray);
//                    result.append(new String(doFinal));
//                }
//            }
//            return result.toString();
//        }catch (NoSuchAlgorithmException e) {
//            throw new RSAException("无此解密算法",e);
//        } catch (NoSuchPaddingException e) {
//            e.printStackTrace();
//            return null;
//        } catch (InvalidKeyException e) {
//            throw new RSAException("解密公钥非法,请检查",e);
//        } catch (IllegalBlockSizeException e) {
//            throw new RSAException("密文长度非法",e);
//        } catch (BadPaddingException e) {
//            throw new RSAException("密文数据已损坏",e);
//        }
//    }
//}