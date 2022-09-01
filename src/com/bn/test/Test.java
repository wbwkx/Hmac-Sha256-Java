package com.bn.test;


import java.util.Arrays;
import java.util.Random;

import com.bn.alg.HmacSha256;
import com.bn.alg.Sha256;
import com.bn.test.LastTimerTest.ITestJob;

class Test {
    public static ITestJob hmacSha256(){
        return new ITestJob() {
            @Override
            public void run() {
                HmacSha256 mac = new HmacSha256();
                Random random = new Random();

                byte[] key = "est, with msg = [java.lang.IllegalArgumentException: Empty key].".getBytes();

                int inputLen = random.nextInt(0xfff);
                byte[] input = TestUtils.getRandomBytes(inputLen);

                byte[] om = mac.hmac_sha256(key,input);
                byte[] oj = TestUtils.hmacSha2(input, key);

                if(!Arrays.equals(om, oj)){
                    throw new RuntimeException(
                            String.format("orig = [%s] om = [%s], while om = [%s]."
                                    , TestUtils.bytesToHexString(input)
                                    , TestUtils.bytesToHexString(om)
                                    , TestUtils.bytesToHexString(oj)));
                }
            }
        };
    }

    public static ITestJob sha256(){
        return new ITestJob() {
            @Override
            public void run() {
                Sha256 s = new Sha256();

                Random random = new Random();
                int len = random.nextInt(5000);

                byte[] input = TestUtils.getRandomBytes(len);
                byte [] om = s.sha256(input);
                byte [] oj = TestUtils.sha2(input);

                if(!Arrays.equals(om, oj)){
                    throw new RuntimeException(
                            String.format("orig = [%s] om = [%s], while om = [%s]."
                                    , TestUtils.bytesToHexString(input)
                                    , TestUtils.bytesToHexString(om)
                                    , TestUtils.bytesToHexString(oj)));
                }
            }
        };
    }
    public static void main(String[] args) {
        LastTimerTest tester = new LastTimerTest();
        tester.test(hmacSha256(), 5, "hmac256");
        tester.test(sha256(), 5, "sha256");
    }
}
