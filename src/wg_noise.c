#include "wg_internal.h"
#include "blake2s.h"
#include <switch.h>
#include <string.h>

static void wg_handshake_init_state(WgHandshakeState* state, const uint8_t peer_public[WG_KEY_LEN]) {
    wg_hash(state->chaining_key, WG_CONSTRUCTION, strlen(WG_CONSTRUCTION));
    wg_hash2(state->hash, state->chaining_key, WG_HASH_LEN, WG_IDENTIFIER, strlen(WG_IDENTIFIER));
    wg_mix_hash(state, peer_public, WG_KEY_LEN);
}

static void wg_compute_mac1(uint8_t mac1[WG_MAC_LEN], const uint8_t peer_public[WG_KEY_LEN], const void* msg, size_t msg_len) {
    uint8_t mac1_key[WG_HASH_LEN];
    wg_hash2(mac1_key, WG_LABEL_MAC1, strlen(WG_LABEL_MAC1), peer_public, WG_KEY_LEN);
    wg_mac(mac1, mac1_key, WG_HASH_LEN, msg, msg_len);
    crypto_wipe(mac1_key, sizeof(mac1_key));
}

int wg_handshake_init(WgTunnel* tun, WgHandshakeInit* msg, WgHandshakeState* state) {
    uint8_t dh_result[WG_KEY_LEN];
    uint8_t key[WG_KEY_LEN];
    uint8_t timestamp[WG_TIMESTAMP_LEN];

    wg_handshake_init_state(state, tun->peer_public);

    randomGet(state->ephemeral_private, WG_KEY_LEN);
    state->ephemeral_private[0] &= 248;
    state->ephemeral_private[31] &= 127;
    state->ephemeral_private[31] |= 64;

    crypto_x25519_public_key(msg->ephemeral, state->ephemeral_private);

    msg->type = WG_MSG_HANDSHAKE_INIT;
    memset(msg->reserved, 0, sizeof(msg->reserved));
    msg->sender_index = wg_random_index();
    tun->session.old_local_index = tun->session.local_index;
    tun->session.local_index = msg->sender_index;
    tun->session.rekey_in_progress = true;

    wg_mix_hash(state, msg->ephemeral, WG_KEY_LEN);
    wg_kdf1(state->chaining_key, state->chaining_key, msg->ephemeral, WG_KEY_LEN);

    crypto_x25519(dh_result, state->ephemeral_private, tun->peer_public);
    wg_kdf2(state->chaining_key, key, state->chaining_key, dh_result, WG_KEY_LEN);
    wg_aead_encrypt(msg->encrypted_static, key, 0, tun->static_public, WG_KEY_LEN, state->hash, WG_HASH_LEN);
    wg_mix_hash(state, msg->encrypted_static, sizeof(msg->encrypted_static));

    crypto_x25519(dh_result, tun->static_private, tun->peer_public);
    wg_kdf2(state->chaining_key, key, state->chaining_key, dh_result, WG_KEY_LEN);

    wg_timestamp(timestamp);
    wg_aead_encrypt(msg->encrypted_timestamp, key, 0, timestamp, WG_TIMESTAMP_LEN, state->hash, WG_HASH_LEN);
    wg_mix_hash(state, msg->encrypted_timestamp, sizeof(msg->encrypted_timestamp));

    wg_hash(tun->last_initiation_hash, msg, sizeof(WgHandshakeInit) - 2 * WG_MAC_LEN);

    wg_compute_mac1(msg->mac1, tun->peer_public, msg, sizeof(WgHandshakeInit) - 2 * WG_MAC_LEN);

    if (tun->has_cookie) {
        wg_mac(msg->mac2, tun->cookie, WG_COOKIE_LEN, msg, sizeof(WgHandshakeInit) - WG_MAC_LEN);
    } else {
        memset(msg->mac2, 0, WG_MAC_LEN);
    }

    crypto_wipe(dh_result, sizeof(dh_result));
    crypto_wipe(key, sizeof(key));
    crypto_wipe(timestamp, sizeof(timestamp));

    return WG_OK;
}

int wg_handshake_response(WgTunnel* tun, const WgHandshakeResponse* msg, WgHandshakeState* state) {
    uint8_t dh_result[WG_KEY_LEN];
    uint8_t key[WG_KEY_LEN];
    uint8_t psk_temp[WG_HASH_LEN];
    uint8_t decrypted[WG_AEAD_TAG_LEN];

    if (msg->type != WG_MSG_HANDSHAKE_RESPONSE)
        return WG_ERR_HANDSHAKE;

    if (msg->receiver_index != tun->session.local_index)
        return WG_ERR_HANDSHAKE;

    tun->session.remote_index = msg->sender_index;

    wg_mix_hash(state, msg->ephemeral, WG_KEY_LEN);
    wg_kdf1(state->chaining_key, state->chaining_key, msg->ephemeral, WG_KEY_LEN);

    crypto_x25519(dh_result, state->ephemeral_private, msg->ephemeral);
    wg_kdf1(state->chaining_key, state->chaining_key, dh_result, WG_KEY_LEN);

    crypto_x25519(dh_result, tun->static_private, msg->ephemeral);
    wg_kdf1(state->chaining_key, state->chaining_key, dh_result, WG_KEY_LEN);

    if (tun->has_psk) {
        wg_kdf3(state->chaining_key, psk_temp, key, state->chaining_key, tun->preshared_key, WG_KEY_LEN);
        wg_mix_hash(state, psk_temp, WG_HASH_LEN);
    } else {
        uint8_t zero_psk[WG_KEY_LEN] = {0};
        wg_kdf3(state->chaining_key, psk_temp, key, state->chaining_key, zero_psk, WG_KEY_LEN);
        wg_mix_hash(state, psk_temp, WG_HASH_LEN);
    }

    int dec_result = wg_aead_decrypt(decrypted, key, 0, msg->encrypted_nothing, sizeof(msg->encrypted_nothing), state->hash, WG_HASH_LEN);
    wg_log("handshake_response: decrypt=%d", dec_result);
    if (dec_result != 0) {
        crypto_wipe(dh_result, sizeof(dh_result));
        crypto_wipe(key, sizeof(key));
        crypto_wipe(psk_temp, sizeof(psk_temp));
        return WG_ERR_DECRYPT;
    }

    wg_mix_hash(state, msg->encrypted_nothing, sizeof(msg->encrypted_nothing));

    wg_kdf2(tun->session.sending_key, tun->session.receiving_key, state->chaining_key, NULL, 0);
    tun->session.sending_counter = 0;
    tun->session.receiving_counter = 0;
    tun->session.last_handshake = wg_time_now();
    tun->session.valid = true;
    tun->session.rekey_in_progress = false;

    crypto_wipe(dh_result, sizeof(dh_result));
    crypto_wipe(key, sizeof(key));
    crypto_wipe(psk_temp, sizeof(psk_temp));
    crypto_wipe(state, sizeof(*state));

    return WG_OK;
}
