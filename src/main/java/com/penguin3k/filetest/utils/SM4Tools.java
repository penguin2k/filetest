package com.penguin3k.filetest.utils;

import java.io.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import cn.hutool.core.io.FileUtil;
import cn.hutool.core.io.IoUtil;
import org.bouncycastle.jcajce.io.CipherInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.legacy.math.linearalgebra.ByteUtils;


public class SM4Tools {
    public static void main(String[] args) throws Exception {

        String sp = "E:/code/filetest/test.doc";//原始文件
        String dp = "E:/code/filetest/demo/test-enc.doc";//加密后文件
        String dp2 = "E:/code/filetest/demo/test.doc";//解密后文件

        // String key = "05d986b1141227cb20d46d0b56202024";
        // byte[] keyData = ByteUtils.fromHexString(key);
        //加密文件
        encryptFile(sp,dp);
        System.out.println("加密成功");
        //解密文件
        decryptFile(dp,dp2);
        System.out.println("解密成功");
    }
    private static String key = "0123456789abcdeffedcba9876543210";
    //使用到的密钥对文件加密
    private static final byte[] keyData = ByteUtils.fromHexString(key);

    static{
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null){
            //No such provider: BC
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    //生成 Cipher
    public static Cipher generateCipher(int mode,byte[] keyData) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        Cipher cipher = Cipher.getInstance("SM4/ECB/PKCS5Padding", BouncyCastleProvider.PROVIDER_NAME);
        Key sm4Key = new SecretKeySpec(keyData, "SM4");
        cipher.init(mode, sm4Key);
        return cipher;
    }


    //加密文件
    public static void encryptFile(String sourcePath,String targetPath){
        //加密文件
        try {
            Cipher cipher = generateCipher(Cipher.ENCRYPT_MODE,keyData);
            CipherInputStream cipherInputStream = new CipherInputStream(new FileInputStream(sourcePath), cipher);
            FileUtil.writeFromStream(cipherInputStream, targetPath);
            IoUtil.close(cipherInputStream);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        //BufferedReader
    }


    /**
     * 解密文件
     * @param sourcePath 待解密的文件路径
     * @param targetPath 解密后的文件路径
     */
    public static void decryptFile(String sourcePath, String targetPath) {
        FileInputStream in =null;
        ByteArrayInputStream byteArrayInputStream =null;
        OutputStream out = null;
        CipherOutputStream cipherOutputStream=null;
        try {
            in = new FileInputStream(sourcePath);
            byte[] bytes = IoUtil.readBytes(in);
            byteArrayInputStream = IoUtil.toStream(bytes);

            Cipher cipher = generateCipher(Cipher.DECRYPT_MODE,keyData);

            out = new FileOutputStream(targetPath);
            cipherOutputStream = new CipherOutputStream(out, cipher);
            IoUtil.copy(byteArrayInputStream, cipherOutputStream);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }finally {
            IoUtil.close(cipherOutputStream);
            IoUtil.close(out);
            IoUtil.close(byteArrayInputStream);
            IoUtil.close(in);
        }
    }
}