package com.bn.test;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

class TestUtils {
    public static byte[] getRandomBytes(int length){
        Random random = new Random();
        byte[] buffer = new byte[length];
        for(int i = 0 ; i < length ; i++ ){
            buffer[i] = (byte) random.nextInt(0xff);
        }
        return buffer;
    }

    public static byte[] hmacSha2(byte[] data, byte[] key) {
        if (data == null || key == null) {
            return null;
        }

        SecretKey secretKey = new SecretKeySpec(key, "HmacSHA256");
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(secretKey);
            byte[] hex = mac.doFinal(data);

            return hex;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] sha2(byte[] data) {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
            byte[] result = digest.digest(data);
            return result;
        } catch (Exception e) {
            System.out.println(e.toString());
            e.printStackTrace();
        }
        return null;
    }


    public static String bytesToHexString(byte[] src) {
        StringBuilder stringBuilder = new StringBuilder("");
        if (src == null || src.length <= 0) {
            return null;
        }
        for (byte b : src) {
            int v = b & 0xFF;
            String hv = Integer.toHexString(v);
            if (hv.length() < 2) {
                stringBuilder.append(0);
            }
            stringBuilder.append(hv);
        }
        return stringBuilder.toString();
    }

    public static String getRandomString(int length, boolean complex){
        Random random = new Random();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < length; i++) {
            int number = complex ? random.nextInt(6) : random.nextInt(3);

            long result = 0;
            switch (number){
                case 0: {
                    result = Math.round(Math.random() * 25 + 65);

                    sb.append((char)((int)result));
                    break;
                }
                case 1: {
                    result = Math.round(Math.random() * 25 + 97);
                    sb.append((char)((int)result));
                    break;
                }
                case 2: {
                    sb.append(random.nextInt(10));
                    break;
                }
                case 4: {
                    result = Math.round(Math.random() * 15 + 32);
                    sb.append((char)((int)result));
                    break;
                }
                case 5: {
                    result = Math.round(Math.random()*6 +58);
                    sb.append((char)((int)result));
                    break;
                }
                case 3: {
                    result = Math.round(Math.random()*3 +123);
                    sb.append((char)((int)result));
                    break;
                }
            }
        }
        return sb.toString();
    }
}
