package com.penguin3k.filetest.utils;

import org.apache.http.cookie.SM;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.jupiter.api.Assertions.*;

class SM2UtilTest {

    @Test
    void encrypt() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException {
//        SM2Util sm2Util = new SM2Util();
        SM2Util.encrypt("E:/code/filetest/test.txt","E:/code/filetest/demo/test.txt");
        SM2Util.decrypt("E:/code/filetest/demo/test.txt","E:/code/filetest/demo/testdec.txt");
        SM2Util.getPrivateKeyHex();
        SM2Util.getPublicKeyHex();
    }

    @Test
    void decrypt() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
        SM2Util.decrypt("E:/code/filetest/demo/test.txt","E:/code/filetest/demo/test-dec.txt");
    }
    @Test
    void gen() throws Exception {
        SM2Util.genCertificate();
        SM2Util.genprivatekey();
    }
    @Test
    void getPrivateKeyHex() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
        SM2Util.getPrivateKeyHex();
    }
}