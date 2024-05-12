package com.penguin3k.filetest.controller;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

@RestController
@RequestMapping("/test")
public class testcontroller {
   @PostMapping("/sm4")
    public void test(MultipartFile file) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
       InputStream inputStream = file.getInputStream();
       Security.addProvider(new BouncyCastleProvider());
       String secretkey="SIN-80238023-@@@";
       SecretKey sm4Key = new SecretKeySpec(secretkey.getBytes(),"sm4");
       Cipher cipher = Cipher.getInstance("SM4/ECB/PKCS5Padding", BouncyCastleProvider.PROVIDER_NAME);
       cipher.init(Cipher.ENCRYPT_MODE, sm4Key);
       ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
       byte[] buffer = new byte[1024];
       int bytesRead;
       while ((bytesRead = inputStream.read(buffer)) != -1) {
           byte[] encryptedBytes = cipher.update(buffer, 0, bytesRead);
           outputStream.write(encryptedBytes);
       }
       byte[] finalBytes = cipher.doFinal();
       outputStream.write(finalBytes);
       File targetFile = new File("E:\\code\\test\\2.png");
       //file.transferTo(targetFile);
       Files.write(targetFile.toPath(), outputStream.toByteArray());
       inputStream.close();
       outputStream.close();
    }
}
