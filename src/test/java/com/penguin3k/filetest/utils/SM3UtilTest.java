package com.penguin3k.filetest.utils;

import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

class SM3UtilTest {

    @Test
    void hashSm3() throws NoSuchAlgorithmException {
        String hash = SM3Util.hashSm3("Hello World");
    }

    @Test
    void hashFile() {
        String hash = SM3Util.hashFile("E:/code/filetest/1.jpg");
        System.out.println(hash);
    }
}