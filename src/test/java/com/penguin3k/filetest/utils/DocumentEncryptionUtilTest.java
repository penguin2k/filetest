package com.penguin3k.filetest.utils;

import org.junit.jupiter.api.Test;

import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;


class DocumentEncryptionUtilTest {

    @Test
    void encryptFile() {
        try {
            DocumentEncryptionUtil.encryptFile("SIN-80238023-@@@","E:/code/filetest/test.txt","E:/code/filetest/demo/test.txt");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void decryptFile() {
        try {
            DocumentEncryptionUtil.decryptFile("SIN-80238023-@@@","E:/code/filetest/demo/test.txt","E:/code/filetest/demo/test-dec.txt");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}