package com.penguin3k.filetest.utils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

public class SM3Util {
    public static String hashSm3(String word) throws NoSuchAlgorithmException {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        MessageDigest digest = MessageDigest.getInstance("SM3", provider);
        word = bytesToHexString(digest.digest(word.getBytes(StandardCharsets.UTF_8)));
        System.out.println("SM3：" + word);
        return word;
    }
    public static String hashFile(String sourcePath)
    {
        FileInputStream fileInputStream = null;
        String  result=null;
        try {
            BouncyCastleProvider provider = new BouncyCastleProvider();
            MessageDigest digest = MessageDigest.getInstance("SM3", provider);
            fileInputStream = new FileInputStream(sourcePath);
            byte[] buffer = new byte[4096];
            int length;
            while ((length = fileInputStream.read(buffer)) != -1) {
                digest.update(buffer, 0, length);
            }
            result= bytesToHexString(digest.digest());
            System.out.println("SM3：" + result);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (fileInputStream != null) {
                    fileInputStream.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }

        }
        return result;
    }
    public static String bytesToHexString(byte[] src) {
        StringBuilder stringBuilder = new StringBuilder("");
        if (src == null || src.length <= 0) {
            return null;
        }
        for (int i = 0; i < src.length; i++) {
            int v = src[i] & 0xFF;
            String hv = Integer.toHexString(v);
            if (hv.length() < 2) {
                stringBuilder.append(0);
            }
            stringBuilder.append(hv);
        }
        return stringBuilder.toString();
    }
}
