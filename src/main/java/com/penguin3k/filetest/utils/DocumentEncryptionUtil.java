package com.penguin3k.filetest.utils;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
/**
 * @use 文件的加密和解密
 */
public class DocumentEncryptionUtil {
    // 文件的加密方式
    private static final String ALGORITHM = "AES";

    /**
     * 文件加密
     * @param secretKey  文件加密密钥
     * @param sourceFilePath  需要加密文件地址
     * @param destinationFilePath  加密后文件地址
     */
    public static void encryptFile(String secretKey,String sourceFilePath, String destinationFilePath) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException {
        // 使用密钥字符串生成秘密密钥
        SecretKey secretKeySpec = new SecretKeySpec(secretKey.getBytes(), ALGORITHM);
        // 获取 AES 加密算法的实例
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        // 使用秘密密钥初始化密码 cipher，设置为加密模式
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        // 获取源文件路径
        Path sourcePath = Paths.get(sourceFilePath);
        // 获取目标加密文件路径
        Path destinationPath = Paths.get(destinationFilePath);

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
        }
    }

    /**
     * 文件解密
     * @param secretKey 文件解密密钥
     * @param sourceFilePath 需要解密的文件地址
     * @param destinationFilePath 解密后的文件地址
     */

    public static void decryptFile(String secretKey,String sourceFilePath, String destinationFilePath) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException {
        SecretKey secretKeySpec = new SecretKeySpec(secretKey.getBytes(), ALGORITHM);
        // 使用密钥字符串生成秘密密钥
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        // 获取 AES 加密算法的实例
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        // 使用秘密密钥初始化密码 cipher，设置为解密模式

        Path sourcePath = Paths.get(sourceFilePath);
        // 获取源加密文件路径
        Path destinationPath = Paths.get(destinationFilePath);
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
        }
    }


}

