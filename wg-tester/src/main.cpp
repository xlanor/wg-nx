#include <borealis.hpp>
#include <cstdlib>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

extern "C" {
#include "wireguard.h"
#include "wg_relay.h"
#include "wg_thread.h"
#include "blake2s.h"
#include "blake2s_neon.h"
#include "monocypher.h"
#include "wg_chacha20_neon.h"
#include "wg_poly1305_neon.h"
}

#define DEMO_HOST "demo.wireguard.com"
#define DEMO_TCP_PORT 42912

struct TestResult {
    std::string name;
    bool passed;
};

static std::vector<TestResult> results;

static void hex_to_bytes(uint8_t* out, const char* hex, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned int byte;
        sscanf(hex + i * 2, "%02x", &byte);
        out[i] = (uint8_t)byte;
    }
}

static bool compare_bytes(const uint8_t* a, const uint8_t* b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

static void test_blake2s() {
    uint8_t expected[32];
    hex_to_bytes(expected, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982", 32);

    uint8_t result[32];
    blake2s(result, 32, "abc", 3, NULL, 0);

    results.push_back({"BLAKE2s", compare_bytes(result, expected, 32)});
}

static void test_x25519() {
    uint8_t scalar[32], u[32], expected[32], result[32];
    hex_to_bytes(scalar, "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", 32);
    hex_to_bytes(u, "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", 32);
    hex_to_bytes(expected, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", 32);

    crypto_x25519(result, scalar, u);

    results.push_back({"X25519", compare_bytes(result, expected, 32)});
}

static void test_chacha20_poly1305() {
    uint8_t key[32];
    hex_to_bytes(key, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", 32);

    uint8_t nonce[12];
    hex_to_bytes(nonce, "070000004041424344454647", 12);

    const char* plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    size_t plaintext_len = strlen(plaintext);

    uint8_t aad[12];
    hex_to_bytes(aad, "50515253c0c1c2c3c4c5c6c7", 12);

    uint8_t expected_tag[16];
    hex_to_bytes(expected_tag, "1ae10b594f09e26a7e902ecbd0600691", 16);

    uint8_t ciphertext[128];
    uint8_t tag[16];

    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, key, nonce);
    crypto_aead_write(&ctx, ciphertext, tag, aad, 12, (const uint8_t*)plaintext, plaintext_len);

    results.push_back({"AEAD Encrypt", compare_bytes(tag, expected_tag, 16)});
}

static void test_chacha20_neon() {
    if (!wg_chacha20_neon_available()) {
        results.push_back({"ChaCha20 NEON", false});
        return;
    }

    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;

    uint8_t nonce[12];
    hex_to_bytes(nonce, "000000090000004a00000000", 12);

    uint8_t expected[64];
    hex_to_bytes(expected,
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e", 64);

    uint8_t block[64];
    wg_chacha20_block_neon(block, key, nonce, 1);

    bool block_ok = compare_bytes(block, expected, 64);

    uint8_t plain[128], cipher[128], dec[128];
    memset(plain, 0x42, 128);
    wg_chacha20_neon(cipher, plain, 128, key, nonce, 1);
    wg_chacha20_neon(dec, cipher, 128, key, nonce, 1);
    bool roundtrip_ok = compare_bytes(dec, plain, 128);

    results.push_back({"ChaCha20 NEON", block_ok && roundtrip_ok});
}

static void test_blake2s_neon() {
    if (!blake2s_neon_available()) {
        results.push_back({"BLAKE2s NEON", false});
        return;
    }

    uint8_t expected[32];
    hex_to_bytes(expected, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982", 32);

    uint8_t result[32];
    blake2s(result, 32, "abc", 3, NULL, 0);

    results.push_back({"BLAKE2s NEON", compare_bytes(result, expected, 32)});
}

static void test_aead_neon() {
    if (!wg_chacha20_neon_available()) {
        results.push_back({"AEAD NEON", false});
        return;
    }

    uint8_t key[32];
    hex_to_bytes(key, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", 32);

    uint8_t aad[12];
    hex_to_bytes(aad, "50515253c0c1c2c3c4c5c6c7", 12);

    const char* plaintext = "Test message for AEAD";
    size_t plaintext_len = strlen(plaintext);

    uint8_t cipher[256];
    uint8_t decrypted[256];

    wg_aead_neon_encrypt(cipher, key, 1, plaintext, plaintext_len, aad, 12);
    int result = wg_aead_neon_decrypt(decrypted, key, 1, cipher, plaintext_len + 16, aad, 12);

    bool ok = (result == 0) && compare_bytes(decrypted, (const uint8_t*)plaintext, plaintext_len);

    results.push_back({"AEAD NEON", ok});
}

static void test_mutex() {
    WgMutex mutex;
    bool ok = wg_mutex_init(&mutex, false) == 0;
    if (ok) {
        wg_mutex_lock(&mutex);
        wg_mutex_unlock(&mutex);
        wg_mutex_fini(&mutex);
    }
    results.push_back({"Mutex", ok});
}

static void test_cond() {
    WgCond cond;
    bool ok = wg_cond_init(&cond) == 0;
    if (ok) wg_cond_fini(&cond);
    results.push_back({"Cond", ok});
}

static void test_stop_cond() {
    WgStopCond stop;
    bool ok = wg_stop_cond_init(&stop) == 0;
    bool check1 = false, check2 = false;
    if (ok) {
        check1 = !wg_stop_cond_check(&stop);
        wg_stop_cond_signal(&stop);
        check2 = wg_stop_cond_check(&stop);
        wg_stop_cond_fini(&stop);
    }
    results.push_back({"StopCond", ok && check1 && check2});
}

static void test_keypair() {
    uint8_t priv[32], pub[32];
    wg_generate_keypair(priv, pub);

    char b64[64];
    bool to_ok = wg_key_to_base64(b64, sizeof(b64), pub) == 0;

    uint8_t decoded[32];
    bool from_ok = wg_key_from_base64(decoded, b64) == 0;
    bool match = compare_bytes(decoded, pub, 32);

    results.push_back({"Keypair + Base64", to_ok && from_ok && match});
}

static void test_thread_create() {
    WgThread thread;
    bool created = wg_thread_create(&thread, [](void* arg) -> void* {
        return arg;
    }, (void*)0x1234) == 0;

    void* retval = nullptr;
    bool joined = false;
    if (created) {
        joined = wg_thread_join(&thread, &retval) == 0;
    }

    results.push_back({"Thread Create/Join", created && joined && retval == (void*)0x1234});
}

static void test_wg_init() {
    uint8_t priv[32], pub[32], peer_pub[32];
    wg_generate_keypair(priv, pub);
    wg_generate_keypair(peer_pub, peer_pub);

    WgConfig config = {};
    memcpy(config.private_key, priv, 32);
    memcpy(config.peer_public_key, peer_pub, 32);
    config.tunnel_ip.s_addr = inet_addr("10.0.0.2");
    strncpy(config.endpoint_host, "127.0.0.1", sizeof(config.endpoint_host));
    config.endpoint_port = 51820;
    config.keepalive_interval = 25;
    config.has_preshared_key = 0;

    WgTunnel* tun = wg_init(&config);
    bool ok = tun != nullptr;

    if (tun) {
        struct in_addr ip;
        wg_get_ip(tun, &ip);
        ok = ok && (ip.s_addr == inet_addr("10.0.0.2"));
        wg_close(tun);
    }

    results.push_back({"WG Init/Close", ok});
}

static void test_relay() {
    uint8_t priv[32], pub[32], peer_pub[32];
    wg_generate_keypair(priv, pub);
    wg_generate_keypair(peer_pub, peer_pub);

    WgConfig config = {};
    memcpy(config.private_key, priv, 32);
    memcpy(config.peer_public_key, peer_pub, 32);
    config.tunnel_ip.s_addr = inet_addr("10.0.0.2");
    strncpy(config.endpoint_host, "127.0.0.1", sizeof(config.endpoint_host));
    config.endpoint_port = 51820;
    config.keepalive_interval = 25;
    config.has_preshared_key = 0;

    WgTunnel* tun = wg_init(&config);
    bool ok = tun != nullptr;

    WgRelay* relay = nullptr;
    if (ok) {
        relay = wg_relay_create(tun, 0);
        ok = ok && (relay != nullptr);
    }

    uint16_t port = 0;
    if (ok) {
        port = wg_relay_get_port(relay);
        ok = ok && (port > 0);
    }

    if (relay) wg_relay_destroy(relay);
    if (tun) wg_close(tun);

    results.push_back({"Relay Create", ok});
}

static bool get_demo_config(uint8_t* server_pub, uint16_t* udp_port, char* my_ip, const char* my_pub_b64) {
    struct hostent* he = gethostbyname(DEMO_HOST);
    if (!he) return false;

    int tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sock < 0) return false;

    struct sockaddr_in tcp_addr = {};
    tcp_addr.sin_family = AF_INET;
    tcp_addr.sin_port = htons(DEMO_TCP_PORT);
    memcpy(&tcp_addr.sin_addr, he->h_addr_list[0], he->h_length);

    if (connect(tcp_sock, (struct sockaddr*)&tcp_addr, sizeof(tcp_addr)) < 0) {
        close(tcp_sock);
        return false;
    }

    char request[128];
    snprintf(request, sizeof(request), "%s\n", my_pub_b64);
    send(tcp_sock, request, strlen(request), 0);

    char response[512];
    int resp_len = recv(tcp_sock, response, sizeof(response) - 1, 0);
    close(tcp_sock);

    if (resp_len <= 0) return false;
    response[resp_len] = '\0';

    char server_pub_b64[64] = {};
    int port = 0;

    char* line = strtok(response, "\n");
    while (line) {
        if (strncmp(line, "OK:", 3) == 0)
            sscanf(line, "OK:%63[^:]:%d:%31s", server_pub_b64, &port, my_ip);
        line = strtok(NULL, "\n");
    }

    if (port == 0) return false;

    wg_key_from_base64(server_pub, server_pub_b64);
    *udp_port = (uint16_t)port;
    return true;
}

static std::string rekey_error_detail;

static void test_udp_send() {
    struct hostent* he = gethostbyname(DEMO_HOST);
    if (!he) {
        results.push_back({"UDP Send", false});
        return;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        results.push_back({"UDP Send (sock)", false});
        return;
    }

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DEMO_TCP_PORT);
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

    const char* msg = "test";
    ssize_t sent = sendto(sock, msg, 4, 0, (struct sockaddr*)&addr, sizeof(addr));
    close(sock);

    results.push_back({"UDP Send", sent == 4});
}

static void test_rekey_integration() {
    uint8_t priv[32], pub[32];
    wg_generate_keypair(priv, pub);

    char pub_b64[64];
    wg_key_to_base64(pub_b64, sizeof(pub_b64), pub);

    uint8_t server_pub[32];
    uint16_t server_port;
    char my_ip[32];

    if (!get_demo_config(server_pub, &server_port, my_ip, pub_b64)) {
        rekey_error_detail = "network";
        results.push_back({"Rekey", false});
        return;
    }

    WgConfig config = {};
    memcpy(config.private_key, priv, 32);
    memcpy(config.peer_public_key, server_pub, 32);
    inet_pton(AF_INET, my_ip, &config.tunnel_ip);
    strncpy(config.endpoint_host, DEMO_HOST, sizeof(config.endpoint_host));
    config.endpoint_port = server_port;
    config.keepalive_interval = 25;
    config.has_preshared_key = 0;

    WgTunnel* tun = wg_init(&config);
    if (!tun) {
        rekey_error_detail = "init failed";
        results.push_back({"Rekey", false});
        return;
    }

    int err = wg_connect(tun);
    if (err != WG_OK) {
        const char* err_name = "?";
        if (err == -2) err_name = "SOCKET";
        else if (err == -3) err_name = "HANDSHAKE";
        else if (err == -4) err_name = "TIMEOUT";
        rekey_error_detail = fmt::format("p:{} {}", server_port, err_name);
        wg_close(tun);
        results.push_back({"Rekey", false});
        return;
    }

    uint32_t idx1 = wg_get_session_index(tun);

    brls::Logger::info("[DEBUG] calling wg_start");
    err = wg_start(tun);
    brls::Logger::info("[DEBUG] wg_start returned {}", err);
    if (err != WG_OK) {
        rekey_error_detail = fmt::format("start err={}", err);
        wg_close(tun);
        results.push_back({"Rekey", false});
        return;
    }

    brls::Logger::info("[DEBUG] calling wg_rekey");
    err = wg_rekey(tun);
    if (err != WG_OK) {
        rekey_error_detail = fmt::format("rekey err={}", err);
        wg_close(tun);
        results.push_back({"Rekey", false});
        return;
    }

    uint32_t idx2 = wg_get_session_index(tun);

    wg_close(tun);

    rekey_error_detail = fmt::format("idx {}→{}", idx1, idx2);
    results.push_back({"Rekey", idx1 != idx2});
}

static std::string poly1305_error_detail;

static void log_hex(const char* label, const uint8_t* data, size_t len) {
    /* Log in chunks of 16 bytes to avoid line wrapping issues */
    brls::Logger::info("[POLY] {}:", label);
    for (size_t offset = 0; offset < len; offset += 16) {
        std::string hex = "  ";
        size_t chunk = (len - offset > 16) ? 16 : (len - offset);
        for (size_t i = 0; i < chunk; i++) {
            hex += fmt::format("{:02x}", data[offset + i]);
            if (i % 4 == 3 && i < chunk - 1) hex += " ";
        }
        brls::Logger::info("{}", hex);
    }
}

static void test_poly1305_rfc() {
    brls::Logger::info("[POLY] === RFC 8439 Poly1305 Test ===");

    /* RFC 8439 Section 2.5.2 test vector */
    uint8_t key[32];
    hex_to_bytes(key,
        "85d6be7857556d337f4452fe42d506a8"
        "0103808afb0db2fd4abff6af4149f51b", 32);

    const char* message = "Cryptographic Forum Research Group";
    size_t msg_len = strlen(message);

    uint8_t expected[16];
    hex_to_bytes(expected, "a8061dc1305136c6c22b8baf0c0127a9", 16);

    uint8_t neon_tag[16];
    uint8_t mono_tag[16];

    wg_poly1305(neon_tag, (const uint8_t*)message, msg_len, key);
    crypto_poly1305(mono_tag, (const uint8_t*)message, msg_len, key);

    log_hex("Expected", expected, 16);
    log_hex("NEON    ", neon_tag, 16);
    log_hex("Mono    ", mono_tag, 16);

    bool neon_ok = compare_bytes(neon_tag, expected, 16);
    bool mono_ok = compare_bytes(mono_tag, expected, 16);
    bool match = compare_bytes(neon_tag, mono_tag, 16);

    if (!neon_ok) {
        poly1305_error_detail = "NEON!=RFC";
        brls::Logger::error("[POLY] NEON does not match RFC expected!");
    }
    if (!mono_ok) {
        brls::Logger::error("[POLY] Mono does not match RFC expected!");
    }
    if (!match) {
        poly1305_error_detail = "NEON!=Mono";
        brls::Logger::error("[POLY] NEON and Mono results differ!");
    }

    results.push_back({"Poly1305 RFC", neon_ok && match});
}

static void test_poly1305_lengths() {
    brls::Logger::info("[POLY] === Various Length Tests ===");

    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 0x80);

    uint8_t message[256];
    for (int i = 0; i < 256; i++) message[i] = (uint8_t)i;

    bool all_pass = true;
    size_t test_lengths[] = {0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128};

    for (size_t t = 0; t < sizeof(test_lengths)/sizeof(test_lengths[0]); t++) {
        size_t len = test_lengths[t];
        uint8_t neon_tag[16];
        uint8_t mono_tag[16];

        if (len == 0) {
            wg_poly1305(neon_tag, nullptr, 0, key);
            crypto_poly1305(mono_tag, (const uint8_t*)"", 0, key);
        } else {
            wg_poly1305(neon_tag, message, len, key);
            crypto_poly1305(mono_tag, message, len, key);
        }

        if (!compare_bytes(neon_tag, mono_tag, 16)) {
            brls::Logger::error("[POLY] FAIL at len={}", len);
            log_hex("  NEON", neon_tag, 16);
            log_hex("  Mono", mono_tag, 16);
            poly1305_error_detail = fmt::format("len={}", len);
            all_pass = false;
        }
    }

    if (all_pass) {
        brls::Logger::info("[POLY] All length tests passed");
    }

    results.push_back({"Poly1305 Lengths", all_pass});
}

static void test_poly1305_aead_compat() {
    brls::Logger::info("[POLY] === AEAD Compatibility Test ===");

    uint8_t key[32];
    hex_to_bytes(key, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", 32);

    uint8_t aad[12];
    hex_to_bytes(aad, "50515253c0c1c2c3c4c5c6c7", 12);

    const char* plaintext = "Test AEAD message";
    size_t plen = strlen(plaintext);

    /* Use WireGuard nonce format: 4 zero bytes + 8-byte little-endian counter */
    uint64_t counter = 42;

    /* Build nonce in WireGuard format */
    uint8_t wg_nonce[12] = {0};
    wg_nonce[4] = (uint8_t)(counter);
    wg_nonce[5] = (uint8_t)(counter >> 8);
    wg_nonce[6] = (uint8_t)(counter >> 16);
    wg_nonce[7] = (uint8_t)(counter >> 24);
    wg_nonce[8] = (uint8_t)(counter >> 32);
    wg_nonce[9] = (uint8_t)(counter >> 40);
    wg_nonce[10] = (uint8_t)(counter >> 48);
    wg_nonce[11] = (uint8_t)(counter >> 56);

    brls::Logger::info("[POLY] counter={}", counter);
    log_hex("WG nonce", wg_nonce, 12);

    /* Step 1: Compare poly1305 key derivation (ChaCha20 block 0) */
    brls::Logger::info("[POLY] --- Poly1305 Key Derivation ---");

    uint8_t neon_poly_key[64];
    wg_chacha20_block_neon(neon_poly_key, key, wg_nonce, 0);

    uint8_t mono_poly_key[64];
    crypto_chacha20_ietf(mono_poly_key, NULL, 64, key, wg_nonce, 0);

    log_hex("NEON polykey", neon_poly_key, 32);
    log_hex("Mono polykey", mono_poly_key, 32);

    bool polykey_match = compare_bytes(neon_poly_key, mono_poly_key, 32);
    if (!polykey_match) {
        brls::Logger::error("[POLY] POLY KEY MISMATCH! ChaCha20 block 0 differs!");
        poly1305_error_detail = "polykey";
    }

    /* Step 2: Compare ChaCha20 encryption (block 1+) */
    brls::Logger::info("[POLY] --- ChaCha20 Encryption ---");

    uint8_t neon_cipher[256];
    wg_chacha20_neon(neon_cipher, (const uint8_t*)plaintext, plen, key, wg_nonce, 1);

    uint8_t mono_cipher[256];
    crypto_chacha20_ietf(mono_cipher, (const uint8_t*)plaintext, plen, key, wg_nonce, 1);

    log_hex("NEON cipher", neon_cipher, plen);
    log_hex("Mono cipher", mono_cipher, plen);

    bool cipher_match = compare_bytes(neon_cipher, mono_cipher, plen);
    if (!cipher_match) {
        brls::Logger::error("[POLY] CIPHER MISMATCH! ChaCha20 encryption differs!");
        if (poly1305_error_detail.empty()) poly1305_error_detail = "cipher";
    }

    /* Step 3: Full AEAD comparison */
    brls::Logger::info("[POLY] --- Full AEAD ---");

    uint8_t mono_out[256];
    uint8_t mono_tag[16];
    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, key, wg_nonce);
    crypto_aead_write(&ctx, mono_out, mono_tag, aad, 12, (const uint8_t*)plaintext, plen);

    uint8_t neon_out[256];
    wg_aead_neon_encrypt(neon_out, key, counter, plaintext, plen, aad, 12);

    log_hex("Mono AEAD tag", mono_tag, 16);
    log_hex("NEON AEAD tag", neon_out + plen, 16);

    bool tag_match = compare_bytes(mono_tag, neon_out + plen, 16);
    if (!tag_match) {
        brls::Logger::error("[POLY] TAG MISMATCH!");
        if (poly1305_error_detail.empty()) poly1305_error_detail = "tag";
    }

    /* Cross-decrypt test */
    uint8_t dec[256];
    uint8_t mono_combined[256];
    memcpy(mono_combined, mono_out, plen);
    memcpy(mono_combined + plen, mono_tag, 16);
    int cross_result = wg_aead_neon_decrypt(dec, key, counter, mono_combined, plen + 16, aad, 12);
    brls::Logger::info("[POLY] NEON decrypt Mono: {}", cross_result);

    bool all_ok = polykey_match && cipher_match && tag_match && (cross_result == 0);
    results.push_back({"Poly1305 AEAD", all_ok});
}

static void test_poly1305_aead_32byte_ad() {
    brls::Logger::info("[POLY] === 32-byte AD Test (Handshake Hash Size) ===");

    uint8_t key[32];
    hex_to_bytes(key, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", 32);

    /* 32-byte AD - same size as WG_HASH_LEN used in handshake decrypt */
    uint8_t aad[32];
    for (int i = 0; i < 32; i++) aad[i] = (uint8_t)(i + 0x10);

    /* Test with empty plaintext like handshake encrypted_nothing */
    const uint8_t empty_plain[1] = {0};
    size_t plen = 0;

    uint64_t counter = 0; /* Handshake uses counter=0 */

    /* Build nonce in WireGuard format */
    uint8_t wg_nonce[12] = {0};
    wg_nonce[4] = (uint8_t)(counter);
    wg_nonce[5] = (uint8_t)(counter >> 8);
    wg_nonce[6] = (uint8_t)(counter >> 16);
    wg_nonce[7] = (uint8_t)(counter >> 24);
    wg_nonce[8] = (uint8_t)(counter >> 32);
    wg_nonce[9] = (uint8_t)(counter >> 40);
    wg_nonce[10] = (uint8_t)(counter >> 48);
    wg_nonce[11] = (uint8_t)(counter >> 56);

    log_hex("32-byte AD", aad, 32);

    /* Monocypher AEAD encrypt */
    uint8_t mono_out[256];
    uint8_t mono_tag[16];
    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, key, wg_nonce);
    crypto_aead_write(&ctx, mono_out, mono_tag, aad, 32, empty_plain, plen);

    /* NEON AEAD encrypt */
    uint8_t neon_out[256];
    wg_aead_neon_encrypt(neon_out, key, counter, empty_plain, plen, aad, 32);

    log_hex("Mono tag (32-AD)", mono_tag, 16);
    log_hex("NEON tag (32-AD)", neon_out + plen, 16);

    bool tag_match = compare_bytes(mono_tag, neon_out + plen, 16);
    if (!tag_match) {
        brls::Logger::error("[POLY] 32-byte AD: TAG MISMATCH!");
        poly1305_error_detail = "32-AD tag";
    }

    /* Cross-decrypt: NEON decrypt Monocypher output */
    uint8_t dec[256];
    uint8_t mono_combined[256];
    memcpy(mono_combined, mono_out, plen);
    memcpy(mono_combined + plen, mono_tag, 16);
    int neon_dec_mono = wg_aead_neon_decrypt(dec, key, counter, mono_combined, plen + 16, aad, 32);
    brls::Logger::info("[POLY] 32-AD: NEON decrypt Mono: {}", neon_dec_mono);

    /* Cross-decrypt: Monocypher decrypt NEON output */
    crypto_aead_ctx ctx2;
    crypto_aead_init_ietf(&ctx2, key, wg_nonce);
    int mono_dec_neon = crypto_aead_read(&ctx2, dec, neon_out + plen, aad, 32, neon_out, plen);
    brls::Logger::info("[POLY] 32-AD: Mono decrypt NEON: {}", mono_dec_neon);

    bool all_ok = tag_match && (neon_dec_mono == 0) && (mono_dec_neon == 0);

    /* Also test with non-empty plaintext */
    const char* test_msg = "Test with 32-byte AD";
    size_t test_len = strlen(test_msg);

    crypto_aead_ctx ctx3;
    crypto_aead_init_ietf(&ctx3, key, wg_nonce);
    crypto_aead_write(&ctx3, mono_out, mono_tag, aad, 32, (const uint8_t*)test_msg, test_len);

    wg_aead_neon_encrypt(neon_out, key, counter, test_msg, test_len, aad, 32);

    bool tag_match2 = compare_bytes(mono_tag, neon_out + test_len, 16);
    if (!tag_match2) {
        brls::Logger::error("[POLY] 32-byte AD (non-empty): TAG MISMATCH!");
        log_hex("Mono tag", mono_tag, 16);
        log_hex("NEON tag", neon_out + test_len, 16);
        if (poly1305_error_detail.empty()) poly1305_error_detail = "32-AD msg tag";
    }

    all_ok = all_ok && tag_match2;
    results.push_back({"AEAD 32-byte AD", all_ok});
}

static void run_all_tests() {
    results.clear();
    test_blake2s();
    test_x25519();
    test_chacha20_poly1305();
    test_chacha20_neon();
    test_poly1305_rfc();
    test_poly1305_lengths();
    test_poly1305_aead_compat();
    brls::Logger::info("[DEBUG] calling 32-byte AD test");
    test_poly1305_aead_32byte_ad();
    brls::Logger::info("[DEBUG] 32-byte AD test done");
    test_aead_neon();
    test_blake2s_neon();
    test_mutex();
    test_cond();
    test_stop_cond();
    test_keypair();
    test_thread_create();
    test_wg_init();
    test_relay();
    test_udp_send();
    test_rekey_integration();
}

class TestActivity : public brls::Activity {
public:
    brls::View* createContentView() override {
        run_all_tests();

        auto* box = new brls::Box(brls::Axis::COLUMN);
        box->setJustifyContent(brls::JustifyContent::CENTER);
        box->setAlignItems(brls::AlignItems::CENTER);

        int passed = 0, failed = 0;
        for (const auto& r : results) {
            if (r.passed) passed++; else failed++;
        }

        auto* title = new brls::Label();
        title->setText("WireGuard Switch Tests");
        title->setFontSize(32);
        title->setMarginBottom(20);
        box->addView(title);

        auto* summary = new brls::Label();
        summary->setText(fmt::format("{} passed, {} failed", passed, failed));
        summary->setFontSize(24);
        summary->setMarginBottom(30);
        box->addView(summary);

        for (const auto& r : results) {
            auto* row = new brls::Box(brls::Axis::ROW);
            row->setAlignItems(brls::AlignItems::CENTER);
            row->setMarginBottom(10);

            auto* name = new brls::Label();
            std::string label = r.name;
            if (r.name == "Rekey" && !rekey_error_detail.empty()) {
                label = fmt::format("Rekey ({})", rekey_error_detail);
            } else if (r.name.find("Poly1305") != std::string::npos && !poly1305_error_detail.empty() && !r.passed) {
                label = fmt::format("{} ({})", r.name, poly1305_error_detail);
            }
            name->setText(label);
            name->setWidth(350);
            row->addView(name);

            auto* status = new brls::Label();
            status->setText(r.passed ? "PASS" : "FAIL");
            status->setTextColor(r.passed ? nvgRGB(0, 200, 0) : nvgRGB(200, 0, 0));
            row->addView(status);

            box->addView(row);
        }

        return box;
    }
};

static void wg_log_handler(const char* msg) {
    brls::Logger::info("[WG] {}", msg);
}

int main(int argc, char* argv[]) {
    brls::Logger::setLogLevel(brls::LogLevel::LOG_DEBUG);

    if (!brls::Application::init()) {
        brls::Logger::error("Unable to init Borealis application");
        return EXIT_FAILURE;
    }

    wg_set_log_callback(wg_log_handler);

    brls::Application::createWindow("WireGuard Tester");
    brls::Application::setGlobalQuit(true);

    brls::Application::pushActivity(new TestActivity());

    while (brls::Application::mainLoop())
        ;

    return EXIT_SUCCESS;
}
