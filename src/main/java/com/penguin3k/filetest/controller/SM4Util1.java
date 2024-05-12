package com.penguin3k.filetest.controller;

import jakarta.xml.bind.DatatypeConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

public class SM4Util1 {
    static{
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null){
            //No such provider: BC
            Security.addProvider(new BouncyCastleProvider());
        }
    }
    private static final String ALGORITHM = "SM4";
    public static String generateKey(String secretKey)
    {
        SecretKey sm4Key= new SecretKeySpec(secretKey.getBytes(), ALGORITHM);
        byte[] keydata=sm4Key.getEncoded();
//        System.out.println(keydata);
//        System.out.println(
//                DatatypeConverter.printHexBinary(keydata)
//        );
//        System.out.println(DatatypeConverter.parseHexBinary(DatatypeConverter.printHexBinary(keydata)));
        return DatatypeConverter.printHexBinary(keydata);
        //return sm4Key;
    }
    public static void encryptFile(String secretKey, File sourceFilePath, File destinationFilePath) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        byte[] keydata= DatatypeConverter.parseHexBinary(secretKey);
        SecretKey sm4Key= new SecretKeySpec(keydata, ALGORITHM);
        System.out.println(DatatypeConverter.printHexBinary(keydata));
        Cipher cipher = Cipher.getInstance("SM4/ECB/PKCS5Padding", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, sm4Key);
        // 获取源文件路径
        Path sourcePath = Paths.get(sourceFilePath.toURI());
        // 获取目标加密文件路径
        Path destinationPath = Paths.get(destinationFilePath.toURI());
        // 创建输入流，读取源文件
        try (InputStream inputStream = Files.newInputStream(sourcePath);
             // 创建输出流，写入加密文件
             OutputStream outputStream = Files.newOutputStream(destinationPath);
             // 创建密码输出流，连接到输出流，并使用密码 cipher 进行加密
             CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher)) {
            // 缓冲区大小
            byte[] buffer = new byte[4096];
            int bytesRead;
            // 读取源文件内容到缓冲区
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                // 将加密后的数据写入加密文件
                cipherOutputStream.write(buffer, 0, bytesRead);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    public static void decryptFile(String secretKey,File sourceFilePath, File destinationFilePath) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        //SecretKey sm4Key= new SecretKeySpec(secretKey.getBytes(), ALGORITHM);
        byte[] keydata= DatatypeConverter.parseHexBinary(secretKey);
        SecretKey sm4Key= new SecretKeySpec(keydata, ALGORITHM);
        Cipher cipher = Cipher.getInstance("SM4/ECB/PKCS5Padding", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, sm4Key);
        Path sourcePath = Paths.get(sourceFilePath.toURI());
        // 获取源加密文件路径
        Path destinationPath = Paths.get(destinationFilePath.toURI());
        // 获取目标解密文件路径
        try (InputStream inputStream = Files.newInputStream(sourcePath);
             // 创建输入流，读取加密文件
             OutputStream outputStream = Files.newOutputStream(destinationPath);
             // 创建输出流，写入解密文件
             CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher)) {
            // 创建密码输入流，连接到输入流，并使用密码 cipher 进行解密
            byte[] buffer = new byte[4096];
            // 缓冲区大小
            int bytesRead;
            while ((bytesRead = cipherInputStream.read(buffer)) != -1) {
                // 读取加密文件内容到缓冲区
                outputStream.write(buffer, 0, bytesRead);
                // 将解密后的数据写入解密文件
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
