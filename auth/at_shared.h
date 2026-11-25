/* at_shared.h - shared secret for payload-key derivation.
 *
 * MUST match the SHARED_SECRET hex string in auth-server/server-lite.js.
 * If the two diverge, decrypt always fails (features silently dead).
 *
 * This is NOT a secret that protects AGAINST a reverser - it's in the
 * binary and extractable. What it protects against is a FAKE server that
 * can produce {"ok":true,"sig":"..."} but doesn't know the shared secret
 * to also compute a matching encrypted payload. Patcher who NOPs the
 * sig check still never sees the game offsets => features silent-dead.
 */
#ifndef AT_SHARED_H
#define AT_SHARED_H

static const unsigned char AT_SHARED_SECRET[32] = {
    0x7E, 0x3A, 0x2C, 0x4F, 0x1D, 0x0B, 0x59, 0x68,
    0xAB, 0x82, 0xCD, 0x14, 0xEF, 0x6A, 0x93, 0xB7,
    0xD8, 0x02, 0x15, 0xCA, 0xEC, 0x7F, 0x49, 0x16,
    0x63, 0xB5, 0xDE, 0x78, 0x92, 0xA0, 0xCF, 0x38
};

/* Expected magic inside the decrypted JSON payload - validates that we
 * got a real payload and not random garbage. If the value we parse for
 * "magic" is not this, treat the payload as invalid. */
#define AT_PAYLOAD_MAGIC 0xA17C0012u

#endif
