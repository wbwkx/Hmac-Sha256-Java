package com.bn.alg;

import com.bn.alg.Sha256.sha256_ctx;
import static com.bn.alg.Sha256.SHA256_BLOCK_SIZE;
import static com.bn.alg.Sha256.SHA256_DIGEST_SIZE;
import static com.bn.alg.Sha256.memset;

public class HmacSha256 {
    private static class hmac_sha256_ctx {
        sha256_ctx ctx_inside = new sha256_ctx();
        sha256_ctx ctx_outside= new sha256_ctx();

        /* for hmac_reinit */
        sha256_ctx ctx_inside_reinit = new sha256_ctx();
        sha256_ctx ctx_outside_reinit = new sha256_ctx();

        byte[] block_ipad = new byte[SHA256_BLOCK_SIZE];
        byte[] block_opad = new byte[SHA256_BLOCK_SIZE];
    } ;

    private void hmac_sha256_init(hmac_sha256_ctx ctx, byte[] key, Sha256 engine) {
        long fill;
        long num;

        byte[] key_used;
        int i;

        int key_size = key.length;
        if (key_size == SHA256_BLOCK_SIZE) {
            key_used = key;
            num = SHA256_BLOCK_SIZE;
        } else {
            if (key_size > SHA256_BLOCK_SIZE) {
                num = SHA256_DIGEST_SIZE;
                byte[] key_temp = engine.sha256(key);
                key_used = key_temp;
            } else { /* key_size > SHA256_BLOCK_SIZE */
                key_used = key;
                num = key_size;
            }
            fill = SHA256_BLOCK_SIZE - num;

            memset(ctx.block_ipad, (int) num, (byte) 0x36, (int) fill);
            memset(ctx.block_opad, (int) num, (byte) 0x5c, (int) fill);
        }

        for (i = 0; i < (int)num; i++) {
            ctx.block_ipad[i] = (byte) (key_used[i] ^ 0x36);
            ctx.block_opad[i] = (byte) (key_used[i] ^ 0x5c);
        }

        engine.sha256_init(ctx.ctx_inside);
        engine.sha256_update(ctx.ctx_inside, ctx.block_ipad);

        engine.sha256_init(ctx.ctx_outside);
        engine.sha256_update(ctx.ctx_outside, ctx.block_opad);

        /* for hmac_reinit */
        ctx.ctx_inside_reinit = ctx.ctx_inside;
        ctx.ctx_outside_reinit = ctx.ctx_outside;
//        memcpy(&ctx->ctx_inside_reinit, &ctx->ctx_inside, sizeof(sha256_ctx));
//        memcpy(&ctx->ctx_outside_reinit, &ctx->ctx_outside, sizeof(sha256_ctx));
    }

    private void hmac_sha256_update(hmac_sha256_ctx ctx, byte[] message, Sha256 engine) {
        engine.sha256_update(ctx.ctx_inside, message);
    }

    private byte[] hmac_sha256_final(hmac_sha256_ctx ctx, Sha256 engine) {
        byte[] digest_inside = new byte[SHA256_DIGEST_SIZE];
        byte[] mac_temp = new byte[SHA256_DIGEST_SIZE];

        engine.sha256_final(ctx.ctx_inside, digest_inside);
        engine.sha256_update(ctx.ctx_outside, digest_inside);
        engine.sha256_final(ctx.ctx_outside, mac_temp);

        return mac_temp;
    }

    public byte[] hmac_sha256(byte[] key, byte[] message) {
        hmac_sha256_ctx ctx = new hmac_sha256_ctx();
        Sha256 engine = new Sha256();
        hmac_sha256_init(ctx, key, engine);
        hmac_sha256_update(ctx, message, engine);
        return hmac_sha256_final(ctx,  engine);
    }

}
