#ifndef WIREGUARD_H
#define WIREGUARD_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

#define WG_KEY_LEN 32
#define WG_MAX_ENDPOINT 256

typedef enum {
    WG_OK = 0,
    WG_ERR_INVALID_CONFIG = -1,
    WG_ERR_SOCKET = -2,
    WG_ERR_HANDSHAKE = -3,
    WG_ERR_TIMEOUT = -4,
    WG_ERR_DECRYPT = -5,
    WG_ERR_NOT_CONNECTED = -6,
    WG_ERR_BUFFER_TOO_SMALL = -7,
    WG_ERR_THREAD = -8,
    WG_ERR_ALREADY_RUNNING = -9,
} WgError;

typedef struct {
    uint8_t private_key[WG_KEY_LEN];
    struct in_addr tunnel_ip;
    uint8_t peer_public_key[WG_KEY_LEN];
    char endpoint_host[WG_MAX_ENDPOINT];
    uint16_t endpoint_port;
    uint16_t keepalive_interval;
    uint8_t preshared_key[WG_KEY_LEN];
    int has_preshared_key;
} WgConfig;

typedef struct WgTunnel WgTunnel;

typedef void (*WgRecvCallback)(void* user, const void* data, size_t len);

WgTunnel* wg_init(const WgConfig* config);
void wg_set_recv_callback(WgTunnel* tun, WgRecvCallback cb, void* user);
int wg_connect(WgTunnel* tun);
int wg_start(WgTunnel* tun);
void wg_stop(WgTunnel* tun);
int wg_send(WgTunnel* tun, const void* data, size_t len);
int wg_recv(WgTunnel* tun, void* buf, size_t len, int timeout_ms);
int wg_get_ip(WgTunnel* tun, struct in_addr* addr);
void wg_close(WgTunnel* tun);

int wg_key_from_base64(uint8_t key[WG_KEY_LEN], const char* base64);
int wg_key_to_base64(char* base64, size_t len, const uint8_t key[WG_KEY_LEN]);
void wg_generate_keypair(uint8_t private_key[WG_KEY_LEN], uint8_t public_key[WG_KEY_LEN]);

int wg_rekey(WgTunnel* tun);
uint32_t wg_get_session_index(WgTunnel* tun);

void wg_set_log_callback(void (*func)(const char* msg));

#endif
