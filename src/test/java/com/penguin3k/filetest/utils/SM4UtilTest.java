package com.penguin3k.filetest.utils;

import cn.hutool.crypto.SmUtil;
import org.junit.jupiter.api.Test;

import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import static org.junit.jupiter.api.Assertions.*;

class SM4UtilTest {

    @Test
    void encryptFile() {
        try {
            SM4Util.encryptFile("SIN-80238023-@@@","E:/code/filetest/1.jpg","E:/code/filetest/demo/1.jpg");
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
            SM4Util.decryptFile("SIN-80238023-@@@","E:/code/filetest/demo/1.jpg","E:/code/filetest/demo/1-dec.jpg");
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
        System.out.println(SM4Util.generateKey("SIN-80238023-@@@"));
    }
}