package com.penguin3k.filetest.utils;

import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.Test;

import javax.naming.InvalidNameException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

import static org.junit.jupiter.api.Assertions.*;

class TestTest {

    @Test
    void getcertificate() throws Exception {
        test.getcertificate("E:\\code\\filetest\\test2.pem");

    }
    @Test
    void signand() throws Exception {
        test.signand();
    }
}