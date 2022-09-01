package com.bn.alg;

import java.math.BigInteger;

public class Sha256 {
    public static final int SHA256_DIGEST_SIZE = (256 / 8);
    public static final int SHA256_BLOCK_SIZE = (512 / 8);

    private static final long[] sha256_h0 =
            {0x6a09e667L, 0xbb67ae85L, 0x3c6ef372L, 0xa54ff53aL,
                    0x510e527fL, 0x9b05688cL, 0x1f83d9abL, 0x5be0cd19L};

    private static final long[] sha256_k =
            {0x428a2f98L, 0x71374491L, 0xb5c0fbcfL, 0xe9b5dba5L,
                    0x3956c25bL, 0x59f111f1L, 0x923f82a4L, 0xab1c5ed5L,
                    0xd807aa98L, 0x12835b01L, 0x243185beL, 0x550c7dc3L,
                    0x72be5d74L, 0x80deb1feL, 0x9bdc06a7L, 0xc19bf174L,
                    0xe49b69c1L, 0xefbe4786L, 0x0fc19dc6L, 0x240ca1ccL,
                    0x2de92c6fL, 0x4a7484aaL, 0x5cb0a9dcL, 0x76f988daL,
                    0x983e5152L, 0xa831c66dL, 0xb00327c8L, 0xbf597fc7L,
                    0xc6e00bf3L, 0xd5a79147L, 0x06ca6351L, 0x14292967L,
                    0x27b70a85L, 0x2e1b2138L, 0x4d2c6dfcL, 0x53380d13L,
                    0x650a7354L, 0x766a0abbL, 0x81c2c92eL, 0x92722c85L,
                    0xa2bfe8a1L, 0xa81a664bL, 0xc24b8b70L, 0xc76c51a3L,
                    0xd192e819L, 0xd6990624L, 0xf40e3585L, 0x106aa070L,
                    0x19a4c116L, 0x1e376c08L, 0x2748774cL, 0x34b0bcb5L,
                    0x391c0cb3L, 0x4ed8aa4aL, 0x5b9cca4fL, 0x682e6ff3L,
                    0x748f82eeL, 0x78a5636fL, 0x84c87814L, 0x8cc70208L,
                    0x90befffaL, 0xa4506cebL, 0xbef9a3f7L, 0xc67178f2L};

    static class sha256_ctx {
        int tot_len;
        int len;
        byte[] block = new byte[2 * SHA256_BLOCK_SIZE];
        long[] h = new long[8];
    }

    public byte[] sha256(byte[] message) {
        sha256_ctx ctx = new sha256_ctx();
        sha256_init(ctx);
        sha256_update(ctx, message);

        byte[] digest = new byte[SHA256_DIGEST_SIZE];
        sha256_final(ctx, digest);

        return digest;
    }

    public void sha256_init(sha256_ctx ctx) {
        int i;
        for (i = 0; i < 8; i++) {
            ctx.h[i] = sha256_h0[i];
        }
        ctx.len = 0;
        ctx.tot_len = 0;
    }

    public void sha256_update(sha256_ctx ctx, byte[] message) {
        int block_nb;
        int new_len, rem_len, tmp_len;
        byte[] shifted_message = null;

        tmp_len = SHA256_BLOCK_SIZE - ctx.len;

        int len = message.length;
        rem_len = len < tmp_len ? len : tmp_len;

        System.arraycopy(message, 0, ctx.block, ctx.len, rem_len);

        if (ctx.len + len < SHA256_BLOCK_SIZE) {
            ctx.len += len;
            return;
        }

        new_len = len - rem_len;
        block_nb = new_len / SHA256_BLOCK_SIZE;

        shifted_message = new byte[message.length - rem_len];
        System.arraycopy(message, rem_len, shifted_message, 0, message.length - rem_len);

        sha256_transf(ctx, ctx.block, 1);
        sha256_transf(ctx, shifted_message, block_nb);

        rem_len = new_len % SHA256_BLOCK_SIZE;

        long p = Integer.toUnsignedLong(block_nb) << 6;
        int pi = BigInteger.valueOf(p).intValue();
        System.arraycopy(shifted_message, pi, ctx.block, 0, rem_len);

        ctx.len = rem_len;
        ctx.tot_len += (Integer.toUnsignedLong(block_nb + 1)) << 6;
    }

    public void sha256_final(sha256_ctx ctx, byte[] digest) {
        int block_nb;
        int pm_len;
        int len_b;
        int i;

        block_nb = (1 + (((SHA256_BLOCK_SIZE - 9) < (ctx.len % SHA256_BLOCK_SIZE)) ? 1 : 0));

        len_b = (ctx.tot_len + ctx.len) << 3;
        pm_len = block_nb << 6;

        memset(ctx.block, ctx.len, (byte) 0x0, pm_len - ctx.len);
        ctx.block[ctx.len] = (byte) 0x80;

        UNPACK32(BigInteger.valueOf(len_b), ctx.block, pm_len - 4);
        sha256_transf(ctx, ctx.block, block_nb);

        for (i = 0; i < 8; i++) {
            UNPACK32(BigInteger.valueOf(ctx.h[i]), digest, i << 2);
        }
    }

    public static void memset(byte[] dest, int destPos, byte ch, int length) {
        for (int i = 0; i < length; i++) {
            dest[destPos + i] = ch;
        }
    }

    private void UNPACK32(BigInteger x, byte[] str, int strPos) {
        BigInteger shift24 = x.shiftRight(24).and(BigInteger.valueOf(0xFF));
        BigInteger shift16 = x.shiftRight(16).and(BigInteger.valueOf(0xFF));
        BigInteger shift8 = x.shiftRight(8).and(BigInteger.valueOf(0xFF));
        BigInteger shift = x.and(BigInteger.valueOf(0xFF));
        str[strPos] = shift24.byteValue();
        str[1 + strPos] = shift16.byteValue();
        str[2 + strPos] = shift8.byteValue();
        str[3 + strPos] = shift.byteValue();
    }

    private BigInteger PACK32(byte[] str, int strPos) {
        BigInteger x = BigInteger.valueOf(((int) str[3 + strPos]) & 0xff)
                .or(BigInteger.valueOf((int) str[2 + strPos] & 0xff).shiftLeft(8))
                .or(BigInteger.valueOf((int) str[1 + strPos] & 0xff).shiftLeft(16))
                .or(BigInteger.valueOf((int) str[0 + strPos] & 0xff).shiftLeft(24));
        return x;
    }

    private static BigInteger SHFR(BigInteger x, int n) {
        long t3 = x.shiftRight(n).longValue() & 0xffffffffL;
        return BigInteger.valueOf(t3);
    }

    private static BigInteger longParseUnsigned(BigInteger value) {
        if (value.compareTo(BigInteger.valueOf(Long.MAX_VALUE)) <= 0)
            return value;
        BigInteger lowValue = value.and(BigInteger.valueOf(0x7fffffffffffffffL));
        BigInteger tmp = new BigInteger("9223372036854775808");
        if (value.and(tmp).compareTo(BigInteger.valueOf(0)) == 0) {
            return lowValue;
        }
        return lowValue.add(BigInteger.valueOf(Long.MAX_VALUE)).add(BigInteger.valueOf(1));
    }

    private static BigInteger ROTR(BigInteger x, int n) {
        int sln = (BigInteger.valueOf(4).shiftLeft(3).intValue() - n);
        BigInteger t2 = x.shiftRight(n);
        long t3 = x.shiftLeft(sln).longValue() & 0xffffffffL;
        BigInteger ret = t2.or(BigInteger.valueOf(t3));
        return ret;
    }

    private static BigInteger SHR(BigInteger x, int n) {
        BigInteger r = x.and(BigInteger.valueOf(0xFFFFFFFFl)).shiftRight(n);
        return longParseUnsigned(r);
    }

    private static BigInteger CH(BigInteger x, BigInteger y, BigInteger z) {
        return (x.and(y)).xor((z.and(x.not())));
    }

    private static BigInteger MAJ(BigInteger x, BigInteger y, BigInteger z) {
        return (x.and(y)).xor(x.and(z)).xor(y.and(z));
    }

    private static BigInteger SHA256_F1(BigInteger x) {
        return ROTR(x, 2).xor(ROTR(x, 13)).xor(ROTR(x, 22));
    }

    private static BigInteger SHA256_F2(BigInteger x) {
        return ROTR(x, 6).xor(ROTR(x, 11)).xor(ROTR(x, 25));
    }

    private static BigInteger SHA256_F3(BigInteger x) {
        return ROTR(x, 7).xor(ROTR(x, 18)).xor(SHFR(x, 3));
    }

    private static BigInteger SHA256_F4(BigInteger x) {
        return ROTR(x, 17).xor(ROTR(x, 19)).xor(SHFR(x, 10));
    }

    private static void SHA256_SCR(long[] w, int i) {
        long m1 = SHA256_F4(BigInteger.valueOf(w[i - 2])).longValue() & 0xffffffffL;
        long m2 = w[i - 7];
        long m3 = SHA256_F3(BigInteger.valueOf(w[i - 15])).longValue() & 0xffffffffL;
        long m4 = w[i - 16];
        w[i] = (m1 + m2 + m3 + m4) & 0xffffffffL;
    }

    private void sha256_transf(sha256_ctx ctx, byte[] message,
                               int block_nb) {
        long[] w = new long[64];
        long[] wv = new long[8];
        long t1, t2;
        byte[] sub_block;
        int i;
        int j;

        for (i = 0; i < (int) block_nb; i++) {
            sub_block = new byte[message.length - (i << 6)];
            System.arraycopy(message, i << 6, sub_block, 0, message.length - (i << 6));

            for (j = 0; j < 16; j++) {
                w[j] = PACK32(sub_block, j << 2).longValue();
            }

            for (j = 16; j < 64; j++) {
                SHA256_SCR(w, j);
            }

            for (j = 0; j < 8; j++) {
                wv[j] = ctx.h[j];
            }

            for (j = 0; j < 64; j++) {
                t1 = (wv[7]
                        + SHA256_F2(BigInteger.valueOf(wv[4])).longValue()
                        + CH(BigInteger.valueOf(wv[4]), BigInteger.valueOf(wv[5]), BigInteger.valueOf(wv[6])).longValue()
                        + sha256_k[j]
                        + w[j]) & 0xffffffffL;
                t2 = (SHA256_F1(BigInteger.valueOf(wv[0])).longValue()
                        + MAJ(BigInteger.valueOf(wv[0]), BigInteger.valueOf(wv[1]), BigInteger.valueOf(wv[2])).longValue()) & 0xffffffffL;
                wv[7] = wv[6];
                wv[6] = wv[5];
                wv[5] = wv[4];
                wv[4] = (wv[3] + t1) & 0xffffffffL;
                wv[3] = wv[2];
                wv[2] = wv[1];
                wv[1] = wv[0];
                wv[0] = (t1 + t2) & 0xffffffffL;
            }

            for (j = 0; j < 8; j++) {
                ctx.h[j] = (wv[j] + ctx.h[j]) & 0xffffffffL;
            }
        }
    }
}


