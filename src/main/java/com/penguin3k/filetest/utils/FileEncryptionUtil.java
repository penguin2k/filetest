package com.penguin3k.filetest.utils;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * @use 文件夹加密和解密
 */
public class FileEncryptionUtil {

    //AES是高级加密标准（Advanced Encryption Standard）的缩写，是一种对称密钥加密算法，常用于数据加密和保护隐私。
    private static final String ALGORITHM = "AES";


    /**
     * 去除文件名扩展名
     * @param fileName 需要操作的文件
     * @return
     */
    private static String removeExtension(String fileName) {
        // 找到文件的最后一个点
        int dotIndex = fileName.lastIndexOf(".");
        // 保证点不是文件名的第一个字符和最后一个字符
        if (dotIndex > 0 && dotIndex < fileName.length() - 1) {
            // 返回有效的扩展名
            return fileName.substring(0, dotIndex);
        }
        // 返回源文件
        return fileName;
    }

    /**
     * 文件夹加密
     * @param secretKey 文件夹加密密钥
     * @param sourceFilePath 需要加密的文件夹
     * @param destinationFilePath 加密后的文件夹地址
     */
    public static void encryptFile(String secretKey,String sourceFilePath, String destinationFilePath) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException {
        // 使用密钥字符串生成秘密密钥
        SecretKey secretKeySpec = new SecretKeySpec(secretKey.getBytes(), ALGORITHM);
        // 获取 AES 加密算法的实例
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        // 使用秘密密钥初始化密码 cipher，设置为加密模式
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        // 获取源文件或文件夹路径
        Path sourcePath = Paths.get(sourceFilePath);
        // 获取目标加密文件或文件夹路径
        Path destinationPath = Paths.get(destinationFilePath);

        if (Files.isDirectory(sourcePath) && !Files.exists(destinationPath)) {
            // 创建目标文件夹
            Files.createDirectories(destinationPath);
            // 遍历源文件夹
            try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(sourcePath)) {
                for (Path filePath : directoryStream) {
                    // 加密后的文件名
                    String encryptedFileName = filePath.getFileName().toString() + ".enc";
                    // 加密后的文件路径
                    String encryptedFilePath = destinationPath.resolve(encryptedFileName).toString();
                    // 递归调用加密方法，处理子文件或子文件夹
                    encryptFile(secretKey,filePath.toString(), encryptedFilePath);
                }
            }
        } else if (Files.isRegularFile(sourcePath)) {
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
    }

    /**
     *
     * @param secretKey 文件夹解密密钥
     * @param sourceFilePath 需要解密的文件夹
     * @param destinationFilePath 解密后的文件夹地址
     */
    public static void decryptFile(String secretKey,String sourceFilePath, String destinationFilePath) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException {
        SecretKey secretKeySpec = new SecretKeySpec(secretKey.getBytes(), ALGORITHM); // 使用密钥字符串生成秘密密钥
        Cipher cipher = Cipher.getInstance(ALGORITHM); // 获取 AES 加密算法的实例
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec); // 使用秘密密钥初始化密码 cipher，设置为解密模式

        Path sourcePath = Paths.get(sourceFilePath); // 获取源加密文件或文件夹路径
        Path destinationPath = Paths.get(destinationFilePath); // 获取目标解密文件或文件夹路径

        if (Files.isDirectory(sourcePath) && !Files.exists(destinationPath)) {
            Files.createDirectories(destinationPath); // 创建目标文件夹
            try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(sourcePath)) { // 遍历源文件夹
                for (Path filePath : directoryStream) {
                    String decryptedFileName = removeExtension(filePath.getFileName().toString()); // 去除文件名的扩展名
                    String decryptedFilePath = destinationPath.resolve(decryptedFileName).toString(); // 解密后的文件路径
                    decryptFile(secretKey,filePath.toString(), decryptedFilePath); // 递归调用解密方法，处理子文件或子文件夹
                }
            }
        } else if (Files.isRegularFile(sourcePath)) {
            try (InputStream inputStream = Files.newInputStream(sourcePath); // 创建输入流，读取加密文件
                 OutputStream outputStream = Files.newOutputStream(destinationPath); // 创建输出流，写入解密文件
                 CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher)) { // 创建密码输入流，连接到输入流，并使用密码 cipher 进行解密
                byte[] buffer = new byte[4096]; // 缓冲区大小
                int bytesRead;
                while ((bytesRead = cipherInputStream.read(buffer)) != -1) { // 读取加密文件内容到缓冲区
                    outputStream.write(buffer, 0, bytesRead); // 将解密后的数据写入解密文件
                }
            }
        }
    }

}
