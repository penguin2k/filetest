package com.penguin3k.filetest.controller;

import com.penguin3k.filetest.utils.SM4Util;
import org.junit.jupiter.api.Test;

import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class SM4Util1Test {

    @Test
    void encryptFile() {
        Random rand = new Random();
        int randomNumber = rand.nextInt(90000) + 10000;
        try {
            SM4Util1.encryptFile(SM4Util1.generateKey("penguin"+randomNumber+"0000"),new File("E:\\code\\filetest\\1.jpg"),new File("E:/code/filetest/demo/1.jpg"));
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void decryptFile() {
        try {
            SM4Util1.decryptFile(SM4Util1.generateKey("SIN-80238023-@@@"),new File("E:/code/filetest/demo/1.jpg"),new File("E:/code/filetest/demo/1-dec.jpg"));
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }
    @Test
    void test(){
        Random rand = new Random();
        int randomNumber = rand.nextInt(90000) + 10000;
        System.out.println(SM4Util1.generateKey("penguin"+randomNumber));
        //System.out.println("/n");
       // System.out.println(SM4Util1.generateKey("penguin"));
        System.out.println(SM4Util1.generateKey("SIN-80238023-@@@"));
    }
}