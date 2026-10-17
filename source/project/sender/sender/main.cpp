extern "C" {
    void vInitializeBL602(void);

    #include <FreeRTOS.h>
    #include <task.h>

    #include <stdio.h>
    #include <stdint.h>
    #include <stddef.h>
    #include <string.h>

    #include <lwip/sockets.h>
    #include <lwip/inet.h>
    #include <lwip/tcpip.h>
    #include <lwip/netif.h>

    #include <mbedtls/ccm.h>
    #include <mbedtls/hkdf.h>
    #include <mbedtls/md.h>
    #include <mbedtls/sha256.h>

    #include <bl_gpio.h>

    #include <easyflash.h>

    extern int errno;
}

#include "pqkem_kem.h"
#include "coap_minimal.h"
#include "security_profile.h"
#include "../../common/pqc_protocol.h"
#include "../../common/pqc_state.h"
#include "../../common/pqc_hash.h"
#include "sender_auth_key.h"
#include "splunk_hec.h"          /* Wi-Fi direct → Splunk HEC */

extern "C" void task_wifi(void *param);
extern "C" volatile uint8_t g_wifi_ready;

#ifndef COAP_CODE_BAD_REQUEST
#define COAP_CODE_BAD_REQUEST 0x80
#endif
#ifndef COAP_CODE_UNAUTHORIZED
#define COAP_CODE_UNAUTHORIZED 0x81
#endif
#ifndef COAP_CODE_FORBIDDEN
#define COAP_CODE_FORBIDDEN 0x83
#endif
#ifndef COAP_CODE_CONTENT
#define COAP_CODE_CONTENT 0x45
#endif
#ifndef COAP_CODE_TOO_MANY_REQUESTS
#define COAP_CODE_TOO_MANY_REQUESTS 0x9D
#endif
#ifndef COAP_CODE_SERVICE_UNAVAILABLE
#define COAP_CODE_SERVICE_UNAVAILABLE 0xA3
#endif

#define WIFI_STACK_SIZE 512
static StackType_t wifi_stack[WIFI_STACK_SIZE];
static StaticTask_t wifi_task;

static constexpr uint8_t LED_PIN  = 5;
static constexpr uint8_t LED_ON   = 1;
static constexpr uint8_t LED_OFF  = 0;

static const size_t AEAD_KEY_LEN        = PQC_AEAD_KEY_LEN;
static const size_t AEAD_NONCE_LEN      = PQC_AEAD_NONCE_LEN;
static const size_t AEAD_TAG_LEN        = PQC_AEAD_TAG_LEN;
static const size_t MAX_PLAINTEXT_LEN   = 64;
static const uint16_t DEMO_PORT         = 5683;
static const size_t MAX_UDP             = 1200;
static const uint8_t MAX_META_RETRIES   = 3;
static const uint8_t MAX_DATA_RETRIES   = 3;

static constexpr uint32_t SENDER_STORE_MAGIC = 0x534E4452u;
static constexpr uint16_t SENDER_STORE_VERSION = 4u;
static uint32_t g_counter_limit=0u;
static bool g_sender_store_failed=false;
static char g_sender_env_key[48];

/* Global message counter so msg_id never repeats across requests */
static uint16_t g_msg_id_counter = 1u;

/*
 * Start CoAP message IDs from a random value instead of always from 1.
 * This is not used as a cryptographic secret, but it avoids predictable
 * CoAP IDs and makes live traffic cleaner in Splunk/Wireshark demos.
 */
static bool init_msg_id_counter(void)
{
    uint8_t rnd[2] = {0u, 0u};
    if (!pqkem_random_bytes(rnd, sizeof(rnd))) return false;

    g_msg_id_counter = (uint16_t)(((uint16_t)rnd[0] << 8) | rnd[1]);
    if (g_msg_id_counter == 0u) {
        g_msg_id_counter = 1u;
    }

    printf("[sender] Random CoAP msg_id seed=0x%04X\r\n",
           (unsigned)g_msg_id_counter);
    return true;
}

static inline uint16_t next_msg_id(void)
{
    if (g_msg_id_counter == 0u) g_msg_id_counter = 1u;
    return g_msg_id_counter++;
}

enum MsgType : uint8_t {
    MSG_DATA = 3
};

struct AeadKey {
    uint8_t key[AEAD_KEY_LEN];
};

struct __attribute__((packed)) SenderStateStore {
    uint32_t magic;
    uint16_t version;
    uint16_t reserved0;
    uint32_t sender_id;
    uint32_t next_counter;
    uint32_t last_gateway_ip;
    uint32_t generation;
    uint32_t crc32;
};



/* Move large buffers out of task stack to avoid stack overflow */
static uint8_t g_gateway_pk[PQKEM_PUBLIC_KEY_BYTES];
static uint8_t g_kem_ct[PQKEM_CIPHERTEXT_BYTES];
static uint8_t g_ss_local[PQKEM_SHARED_SECRET_BYTES];
static DataMsg g_data_msg;
static uint8_t g_rx_buf[MAX_UDP];
static uint8_t g_coap_buf[MAX_UDP];

/* ── Helpers ─────────────────────────────────────────────────────── */

static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printf("%s = ", label);
    for (size_t i = 0; i < len; ++i) {
        printf("%02X", buf[i]);
        if ((i + 1) % 16 == 0) printf("\r\n");
        else printf(" ");
    }
    if (len % 16 != 0) printf("\r\n");
}

/*
 * compare_and_show_fingerprints()
 * Prints both fingerprints side-by-side and marks any differing byte with *.
 * This makes it instantly clear if there is a mismatch and which byte differs.
 */
static bool compare_and_show_fingerprints(
    const uint8_t *computed,
    const uint8_t *provisioned,
    size_t len)
{
    uint8_t diff = 0u;
    for (size_t i = 0; i < len; ++i) {
        diff |= (uint8_t)(computed[i] ^ provisioned[i]);
    }

    if (diff != 0u) {
        printf("[sender] *** FINGERPRINT MISMATCH — byte diff map ***\r\n");
        printf("[sender] Byte | Computed | Provisioned\r\n");
        for (size_t i = 0; i < len; ++i) {
            if (computed[i] != provisioned[i]) {
                printf("[sender]  %02zu  |   %02X      |    %02X    <<<< DIFFER\r\n",
                       i, computed[i], provisioned[i]);
            }
        }
        printf("[sender] Fix: re-run provision_fingerprint.py with the correct fingerprint above\r\n");
        printf("[sender] Then: cd sender && make clean && ./genromap\r\n");
        printf("[sender] Then: blflash flash build_out/sender.bin --port /dev/ttyUSB0\r\n");
        return false;
    }
    return true;
}

static void secure_zero(void *ptr, size_t len)
{
    volatile uint8_t *p = reinterpret_cast<volatile uint8_t *>(ptr);
    while (len--) { *p++ = 0u; }
}

static bool hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t out[PQC_DEVICE_AUTH_TAG_LEN])
{
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) return false;
    return mbedtls_md_hmac(md, key, key_len, data, data_len, out) == 0;
}

static void led_init()
{
    bl_gpio_enable_output(LED_PIN, 0, 0);
    bl_gpio_output_set(LED_PIN, LED_OFF);
}

static void led_on_ms(uint32_t ms)
{
    bl_gpio_output_set(LED_PIN, LED_ON);
    vTaskDelay(pdMS_TO_TICKS(ms));
    bl_gpio_output_set(LED_PIN, LED_OFF);
}

static uint32_t monotonic_ms()
{
    return (uint32_t)xTaskGetTickCount() * (uint32_t)portTICK_PERIOD_MS;
}

static bool sha256_bytes(const uint8_t *data, size_t len,
                         uint8_t out[PQC_PK_FINGERPRINT_LEN])
{
    return pqc_sha256(data, len, out)==0;
}

static bool hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                        const uint8_t *salt, size_t salt_len,
                        const uint8_t *info, size_t info_len,
                        uint8_t *okm, size_t okm_len)
{
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) {
        printf("[sender] mbedtls_md_info_from_type NULL\r\n");
        return false;
    }
    int rc = mbedtls_hkdf(md, salt, salt_len, ikm, ikm_len,
                          info, info_len, okm, okm_len);
    if (rc != 0) printf("[sender] mbedtls_hkdf failed rc=%d\r\n", rc);
    return rc == 0;
}

static bool aead_encrypt(const AeadKey &key,
                         const uint8_t *nonce,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *plaintext, size_t pt_len,
                         uint8_t *ciphertext, uint8_t *tag)
{
    mbedtls_ccm_context ctx;
    mbedtls_ccm_init(&ctx);
    int rc = mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES,
                                key.key, (unsigned int)(AEAD_KEY_LEN * 8));
    if (rc != 0) {
        printf("[sender] ccm_setkey failed rc=%d\r\n", rc);
        mbedtls_ccm_free(&ctx);
        return false;
    }
    rc = mbedtls_ccm_encrypt_and_tag(&ctx, pt_len,
                                     nonce, AEAD_NONCE_LEN,
                                     aad, aad_len,
                                     plaintext, ciphertext,
                                     tag, AEAD_TAG_LEN);
    mbedtls_ccm_free(&ctx);
    if (rc != 0) printf("[sender] ccm_encrypt failed rc=%d\r\n", rc);
    return rc == 0;
}

static bool parse_ipv4_string(const char *ip_str, uint32_t *out_addr)
{
    if (!ip_str || !ip_str[0] || !out_addr) return false;
    struct in_addr addr;
    memset(&addr, 0, sizeof(addr));
    int ok = inet_aton(ip_str, &addr);
    if (!ok) return false;
    *out_addr = addr.s_addr;
    return true;
}

/* ── Flash state ──────────────────────────────────────────────────── */

/* EasyFlash owns placement and wear management. next_counter on disk is an
 * exclusive reservation boundary; a reboot skips all previously reserved IDs. */
static bool sender_state_save(const SenderStateStore *st)
{
    SenderStateStore copy=*st, verify; size_t stored=0;
    copy.crc32=pqc_crc32(&copy,offsetof(SenderStateStore,crc32));
    if(ef_set_env_blob(g_sender_env_key,&copy,sizeof(copy))!=EF_NO_ERR || ef_save_env()!=EF_NO_ERR) return false;
    size_t got=ef_get_env_blob(g_sender_env_key,&verify,sizeof(verify),&stored);
    return got==sizeof(verify) && stored==sizeof(verify) && memcmp(&verify,&copy,sizeof(copy))==0;
}
static bool sender_state_init_or_load(SenderStateStore *st)
{
    if(easyflash_init()!=EF_NO_ERR) return false;
    snprintf(g_sender_env_key,sizeof(g_sender_env_key),"pqc_s_%08lX_%08lX",
        (unsigned long)PQC_SENDER_ID,(unsigned long)PQC_CREDENTIAL_GENERATION);
    size_t stored=0; memset(st,0,sizeof(*st));
    size_t got=ef_get_env_blob(g_sender_env_key,st,sizeof(*st),&stored);
    if(stored==0 && got==0) {
        st->magic=SENDER_STORE_MAGIC; st->version=SENDER_STORE_VERSION;
        st->sender_id=PQC_SENDER_ID; st->generation=PQC_CREDENTIAL_GENERATION; st->next_counter=1;
        if(!sender_state_save(st))return false;
        splunk_send_event("SENDER_STATE_NEW","info","new_identity_state");
    } else if(got!=sizeof(*st)||stored!=sizeof(*st)||st->magic!=SENDER_STORE_MAGIC||
        st->version!=SENDER_STORE_VERSION||st->sender_id!=PQC_SENDER_ID||
        st->generation!=PQC_CREDENTIAL_GENERATION||!st->next_counter||
        st->crc32!=pqc_crc32(st,offsetof(SenderStateStore,crc32))) return false;
    g_counter_limit=st->next_counter; return true;
}
static bool sender_next_sequence(SenderStateStore *st,uint32_t *sequence)
{
    if(g_sender_store_failed) return false;
    if(st->next_counter>=g_counter_limit) {
        uint32_t end=0;
        if(!pqc_reservation_end(st->next_counter,256u,&end))return false;
        SenderStateStore disk=*st; disk.next_counter=end;
        if(!sender_state_save(&disk)) { g_sender_store_failed=true; return false; }
        g_counter_limit=end;
    }
    *sequence=st->next_counter++; return true;
}

/* ── CoAP receive ─────────────────────────────────────────────────── */

static bool recv_coap_response(int sock_fd,
                               const struct sockaddr_in *expected_src,
                               const char *expected_uri,
                               uint16_t expected_msg_id,
                               int timeout_seconds,
                               CoapMessage *cm_out,
                               struct sockaddr_in *src_out)
{
    const uint32_t deadline_ms =
        monotonic_ms() + (uint32_t)(timeout_seconds * 1000);

    while ((int32_t)(deadline_ms - monotonic_ms()) > 0) {
        const uint32_t remain_ms = deadline_ms - monotonic_ms();
        struct timeval tv;
        tv.tv_sec  = (long)(remain_ms / 1000u);
        tv.tv_usec = (long)((remain_ms % 1000u) * 1000u);

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock_fd, &rfds);

        const int sel = select(sock_fd + 1, &rfds, NULL, NULL, &tv);
        if (sel < 0) {
            printf("[sender] select() failed errno=%d\r\n", errno);
            return false;
        }
        if (sel == 0) break; /* timeout */

        struct sockaddr_in src;
        socklen_t srclen = sizeof(src);
        const int n = recvfrom(sock_fd, g_rx_buf, sizeof(g_rx_buf), 0,
                               reinterpret_cast<struct sockaddr *>(&src),
                               &srclen);
        if (n <= 0) continue;

        if (expected_src) {
            if (src.sin_addr.s_addr != expected_src->sin_addr.s_addr ||
                src.sin_port != expected_src->sin_port) continue;
        }

        CoapMessage cm;
        if (!coap_parse(&cm, g_rx_buf, (size_t)n)) continue;
        if (cm.ver != 1u || cm.token_len != 0u) continue;
        if (cm.type != COAP_TYPE_ACK) continue;
        if (cm.msg_id != expected_msg_id) continue;
        if (expected_uri && strcmp(cm.uri_path, expected_uri) != 0) continue;

        if (cm_out)  *cm_out  = cm;
        if (src_out) *src_out = src;
        return true;
    }

    printf("[sender] Timed out waiting for CoAP response uri='%s' msg_id=0x%04X\r\n",
           expected_uri ? expected_uri : "<any>",
           (unsigned)expected_msg_id);
    return false;
}

/* ── Gateway resolution ───────────────────────────────────────────── */

static bool discover_gateway_ip(int sock_fd,
                                struct sockaddr_in *gw_out,
                                int timeout_seconds)
{
#if PQC_ALLOW_BROADCAST_DISCOVERY
    const uint16_t msg_id = next_msg_id();
    const size_t coap_len = coap_build_simple(g_coap_buf, sizeof(g_coap_buf),
                                               COAP_TYPE_CON, COAP_CODE_GET,
                                               msg_id, "pqkem-meta", NULL, 0);
    if (coap_len == 0u) return false;

    int bcast = 1;
    setsockopt(sock_fd, SOL_SOCKET, SO_BROADCAST, &bcast, sizeof(bcast));

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family      = AF_INET;
    dst.sin_port        = htons(DEMO_PORT);
    dst.sin_addr.s_addr = INADDR_BROADCAST;

    if (sendto(sock_fd, g_coap_buf, coap_len, 0,
               reinterpret_cast<const struct sockaddr *>(&dst),
               sizeof(dst)) < 0) {
        printf("[sender] Gateway discovery broadcast send failed errno=%d\r\n", errno);
        return false;
    }

    printf("[sender] Gateway discovery broadcast sent on UDP/%u\r\n",
           (unsigned)DEMO_PORT);

    CoapMessage cm;
    struct sockaddr_in src;
    if (!recv_coap_response(sock_fd, NULL, "pqkem-meta", msg_id,
                            timeout_seconds, &cm, &src)) return false;

    *gw_out = src;
    gw_out->sin_port = htons(DEMO_PORT);

    char ip_str[16] = {0};
    inet_ntoa_r(gw_out->sin_addr, ip_str, sizeof(ip_str));
    printf("[sender] Gateway auto-discovered at %s:%u\r\n",
           ip_str, (unsigned)DEMO_PORT);
    splunk_send_event("GATEWAY_DISCOVERY_OK", "info", "gateway_discovered");
    return true;
#else
    (void)sock_fd; (void)gw_out; (void)timeout_seconds;
    return false;
#endif
}

static bool resolve_gateway_address(int sock_fd,
                                    const SenderStateStore &st,
                                    struct sockaddr_in *gw_out)
{
    memset(gw_out, 0, sizeof(*gw_out));
    gw_out->sin_family = AF_INET;
    gw_out->sin_port   = htons(DEMO_PORT);

    uint32_t ip_addr = 0u;

    /*
     * Gateway IP resolution order:
     *   1. Static IP only when explicitly configured.
     *   2. Live broadcast discovery every boot/cycle refresh.
     *   3. Last saved IP only as fallback.
     *
     * This makes DHCP changes automatic and avoids manually editing the
     * Receiver/Gateway IP every time.
     */
    if (parse_ipv4_string(PQC_GATEWAY_STATIC_IP, &ip_addr)) {
        gw_out->sin_addr.s_addr = ip_addr;
        printf("[sender] Using configured static gateway IP\r\n");
        splunk_send_event("GATEWAY_STATIC_IP", "info", "static_gateway_used");
        return true;
    }

    if (discover_gateway_ip(sock_fd, gw_out, 5)) {
        return true;
    }

    if (st.last_gateway_ip != 0u) {
        gw_out->sin_addr.s_addr = st.last_gateway_ip;
        printf("[sender] Gateway discovery failed; using last saved IP fallback\r\n");
        splunk_send_event("GATEWAY_FALLBACK_IP", "medium", "last_saved_gateway_used");
        return true;
    }

    printf("[sender] No static IP, auto-discovery failed, and no fallback IP\r\n");
    splunk_send_event("GATEWAY_DISCOVERY_FAIL", "high", "gateway_not_found");
    return false;
}

/* ── PK and metadata fetch ────────────────────────────────────────── */

static bool fetch_gateway_pk(int sock_fd, const struct sockaddr_in *gw)
{
    const uint16_t msg_id = next_msg_id();
    const size_t coap_len = coap_build_simple(g_coap_buf, sizeof(g_coap_buf),
                                               COAP_TYPE_CON, COAP_CODE_GET,
                                               msg_id, "pqkem-pk", NULL, 0);
    if (coap_len == 0u) {
        printf("[sender] Failed to build /pqkem-pk request\r\n");
        return false;
    }

    for (uint8_t attempt = 1; attempt <= MAX_META_RETRIES; ++attempt) {
        if (sendto(sock_fd, g_coap_buf, coap_len, 0,
                   reinterpret_cast<const struct sockaddr *>(gw),
                   sizeof(*gw)) < 0) {
            printf("[sender] sendto(/pqkem-pk) failed errno=%d\r\n", errno);
            vTaskDelay(pdMS_TO_TICKS(300 * attempt));
            continue;
        }

        CoapMessage cm;
        if (!recv_coap_response(sock_fd, gw, "pqkem-pk", msg_id, 6, &cm, NULL)) {
            vTaskDelay(pdMS_TO_TICKS(300 * attempt));
            continue;
        }
        if (cm.code != COAP_CODE_CONTENT) {
            printf("[sender] /pqkem-pk code=0x%02X\r\n", (unsigned)cm.code);
            return false;
        }
        if (cm.payload_len != PQKEM_PUBLIC_KEY_BYTES) {
            printf("[sender] /pqkem-pk bad len=%u expected=%u\r\n",
                   (unsigned)cm.payload_len, (unsigned)PQKEM_PUBLIC_KEY_BYTES);
            return false;
        }
        memcpy(g_gateway_pk, cm.payload, PQKEM_PUBLIC_KEY_BYTES);
        return true;
    }
    printf("[sender] /pqkem-pk failed after %u attempts\r\n",
           (unsigned)MAX_META_RETRIES);
    splunk_send_event("SEND_FAILED", "high", "pk_fetch_failed");
    return false;
}

static bool fetch_gateway_metadata(int sock_fd,
                                   const struct sockaddr_in *gw,
                                   GatewayKeyMetadataPayload *meta)
{
    const uint16_t msg_id = next_msg_id();
    const size_t coap_len = coap_build_simple(g_coap_buf, sizeof(g_coap_buf),
                                               COAP_TYPE_CON, COAP_CODE_GET,
                                               msg_id, "pqkem-meta", NULL, 0);
    if (coap_len == 0u) {
        printf("[sender] Failed to build /pqkem-meta request\r\n");
        return false;
    }

    for (uint8_t attempt = 1; attempt <= MAX_META_RETRIES; ++attempt) {
        if (sendto(sock_fd, g_coap_buf, coap_len, 0,
                   reinterpret_cast<const struct sockaddr *>(gw),
                   sizeof(*gw)) < 0) {
            printf("[sender] sendto(/pqkem-meta) failed errno=%d\r\n", errno);
            vTaskDelay(pdMS_TO_TICKS(300 * attempt));
            continue;
        }

        CoapMessage cm;
        if (!recv_coap_response(sock_fd, gw, "pqkem-meta", msg_id, 6, &cm, NULL)) {
            vTaskDelay(pdMS_TO_TICKS(300 * attempt));
            continue;
        }
        if (cm.code != COAP_CODE_CONTENT) {
            printf("[sender] /pqkem-meta code=0x%02X\r\n", (unsigned)cm.code);
            return false;
        }
        if (cm.payload_len != sizeof(*meta)) {
            printf("[sender] /pqkem-meta bad len=%u expected=%u\r\n",
                   (unsigned)cm.payload_len, (unsigned)sizeof(*meta));
            return false;
        }
        memcpy(meta, cm.payload, sizeof(*meta));
        if (meta->magic != PQC_META_MAGIC) {
            printf("[sender] Metadata magic mismatch 0x%08lX\r\n",
                   (unsigned long)meta->magic);
            return false;
        }
        return true;
    }
    return false;
}

/* ── Fingerprint verification — with full diagnostic output ──────── */

static bool verify_gateway_public_key(uint8_t out_fp[PQC_PK_FINGERPRINT_LEN])
{
    if (!sha256_bytes(g_gateway_pk, PQKEM_PUBLIC_KEY_BYTES, out_fp)) {
        printf("[sender] SHA-256 of gateway PK failed\r\n");
        return false;
    }

    print_hex("[sender] Gateway PK fingerprint (computed)", out_fp, PQC_PK_FINGERPRINT_LEN);
    print_hex("[sender] Provisioned fingerprint          ", kProvisionedGatewayPkFingerprint, PQC_PK_FINGERPRINT_LEN);

#if PQC_PK_AUTH_MODE == PQC_PK_AUTH_MODE_STRICT
    if (!pqc_fingerprint_is_provisioned()) {
        printf("[sender] ERROR: STRICT mode but no fingerprint provisioned\r\n");
        printf("[sender] Run: python3 host-tools/provision_fingerprint.py --fingerprint-hex <HEX> ...\r\n");
        return false;
    }

    if (!compare_and_show_fingerprints(out_fp,
                                       kProvisionedGatewayPkFingerprint,
                                       PQC_PK_FINGERPRINT_LEN)) {
        printf("[sender] PK AUTH FAIL: fingerprints differ (see byte map above)\r\n");
        splunk_send_event("PK_AUTH_FAIL", "high", "fingerprint_mismatch");
        return false;
    }

    printf("[sender] PK AUTH OK: fingerprint verified\r\n");
    splunk_send_event("PK_AUTH_OK", "info", "fingerprint_verified");
    return true;
#else
    if (pqc_fingerprint_is_provisioned()) {
        if (!compare_and_show_fingerprints(out_fp,
                                           kProvisionedGatewayPkFingerprint,
                                           PQC_PK_FINGERPRINT_LEN)) {
            printf("[sender] PK AUTH FAIL\r\n");
            splunk_send_event("PK_AUTH_FAIL", "high", "fingerprint_mismatch");
            return false;
        }
        printf("[sender] PK AUTH OK\r\n");
        splunk_send_event("PK_AUTH_OK", "info", "fingerprint_verified");
    } else {
        printf("[sender] TOFU mode — accepting first key seen\r\n");
    }
    return true;
#endif
}

static bool validate_gateway_metadata(const GatewayKeyMetadataPayload &meta,
                                      const uint8_t fp[PQC_PK_FINGERPRINT_LEN])
{
    /* constant-time byte compare */
    uint8_t diff = 0u;
    for (size_t i = 0; i < PQC_PK_FINGERPRINT_LEN; ++i)
        diff |= (uint8_t)(meta.fingerprint[i] ^ fp[i]);
    if (diff != 0u) {
        printf("[sender] Metadata/public-key fingerprint mismatch\r\n");
        splunk_send_event("PK_AUTH_FAIL", "high", "metadata_fingerprint_mismatch");
        return false;
    }
    if (meta.status == PQC_KEY_STATUS_REVOKED) {
        printf("[sender] Gateway key is REVOKED\r\n");
        return false;
    }
    if (meta.rotation_required || meta.status == PQC_KEY_STATUS_ROTATION_REQUIRED) {
        printf("[sender] Gateway reports key rotation required\r\n");
        return false;
    }
    return true;
}

/* ── Protected message send ───────────────────────────────────────── */

static bool send_protected_message(int sock_fd,
                                   SenderStateStore *state,
                                   const struct sockaddr_in *gw)
{
    uint8_t gateway_fp[PQC_PK_FINGERPRINT_LEN];
    GatewayKeyMetadataPayload meta;
    memset(&meta, 0, sizeof(meta));

    /* Step 1 — fetch PK */
    if (!fetch_gateway_pk(sock_fd, gw)) {
        printf("[sender] ERROR: failed to get gateway PK\r\n");
        return false;
    }

    /* Step 2 — verify fingerprint (with full diagnostic) */
    if (!verify_gateway_public_key(gateway_fp)) {
        return false;
    }

    /* Step 3 — fetch metadata and cross-check fingerprint */
    if (!fetch_gateway_metadata(sock_fd, gw, &meta)) {
        printf("[sender] ERROR: failed to get gateway metadata\r\n");
        return false;
    }
    if (!validate_gateway_metadata(meta, gateway_fp)) {
        return false;
    }

    /* Step 4 — ML-KEM encapsulate */
    memset(g_kem_ct,    0, sizeof(g_kem_ct));
    memset(g_ss_local,  0, sizeof(g_ss_local));

    const uint32_t t0 = monotonic_ms();
    if (!pqkem_encapsulate(g_gateway_pk, g_kem_ct, g_ss_local)) {
        printf("[sender] pqkem_encapsulate failed\r\n");
        secure_zero(g_ss_local, sizeof(g_ss_local));
        return false;
    }
    const uint32_t kem_ms = monotonic_ms() - t0;
    printf("[sender] KEM encapsulate: %lu ms\r\n", (unsigned long)kem_ms);

    /* Step 5 — HKDF */
    AeadKey aead_key;
    memset(&aead_key, 0, sizeof(aead_key));
    const uint8_t info[] = PQC_HKDF_INFO;
    const uint32_t hkdf_t0 = monotonic_ms();
    if (!hkdf_sha256(g_ss_local, PQKEM_SHARED_SECRET_BYTES,
                     NULL, 0,
                     info, sizeof(info) - 1,
                     aead_key.key, sizeof(aead_key.key))) {
        secure_zero(g_ss_local, sizeof(g_ss_local));
        return false;
    }
    const uint32_t hkdf_ms = monotonic_ms() - hkdf_t0;
    secure_zero(g_ss_local, sizeof(g_ss_local));
    splunk_send_event("KEM_HKDF_DONE", "info", "aes_256_ccm_key_derived");

    /* Step 6 — Build message header */
    const char *plaintext = "Hello from PQC sender!";
    const size_t pt_len   = strlen(plaintext);

    uint8_t nonce[AEAD_NONCE_LEN];
    memset(nonce, 0, sizeof(nonce));
    if (!pqkem_random_bytes(nonce, sizeof(nonce))) {
        secure_zero(&aead_key,sizeof(aead_key)); return false;
    }

    memset(&g_data_msg, 0, sizeof(g_data_msg));
    g_data_msg.type       = MSG_DATA;
    g_data_msg.version    = (uint8_t)PQC_PROTOCOL_VERSION;
    g_data_msg.kem_ct_len = (uint16_t)sizeof(g_kem_ct);
    g_data_msg.text_len   = (uint16_t)pt_len;
    g_data_msg.key_id     = meta.key_id;
    g_data_msg.sender_id  = state->sender_id;
    g_data_msg.generation = PQC_CREDENTIAL_GENERATION;
    uint32_t sequence=0;
    if(!sender_next_sequence(state,&sequence)) {
        secure_zero(&aead_key,sizeof(aead_key));
        splunk_send_event("STATE_PERSIST_FAIL","critical","send_aborted"); return false;
    }
    g_data_msg.sequence=sequence;
    splunk_set_context(state->sender_id,g_data_msg.generation,sequence);
    memcpy(g_data_msg.nonce, nonce, sizeof(nonce));

    state->last_gateway_ip = gw->sin_addr.s_addr;


    /* Step 7 — AEAD encrypt (AAD = full header) */
    const size_t aad_len    = offsetof(DataMsg, buf);
    uint8_t ciphertext[MAX_PLAINTEXT_LEN];
    uint8_t tag[AEAD_TAG_LEN];
    memset(ciphertext, 0, sizeof(ciphertext));
    memset(tag,        0, sizeof(tag));

    const uint32_t aead_t0 = monotonic_ms();
    if (!aead_encrypt(aead_key,
                      g_data_msg.nonce,
                      reinterpret_cast<const uint8_t *>(&g_data_msg), aad_len,
                      reinterpret_cast<const uint8_t *>(plaintext), pt_len,
                      ciphertext, tag)) {
        secure_zero(&aead_key, sizeof(aead_key));
        return false;
    }
    const uint32_t aead_ms = monotonic_ms() - aead_t0;
    secure_zero(&aead_key, sizeof(aead_key));
    splunk_send_event("AEAD_ENCRYPT_DONE", "info", "aes_256_ccm_message_encrypted");

    /* Step 8 — Pack CoAP payload */
    memcpy(g_data_msg.buf,                          g_kem_ct,    sizeof(g_kem_ct));
    memcpy(g_data_msg.buf + sizeof(g_kem_ct),       ciphertext,  pt_len);
    memcpy(g_data_msg.buf + sizeof(g_kem_ct) + pt_len, tag,      sizeof(tag));
    secure_zero(ciphertext, sizeof(ciphertext));

    /* Per-device authentication: HMAC covers header + KEM CT + ciphertext + CCM tag. */
    const size_t auth_input_len = aad_len + sizeof(g_kem_ct) + pt_len + sizeof(tag);
    uint8_t device_auth_tag[PQC_DEVICE_AUTH_TAG_LEN];
    memset(device_auth_tag, 0, sizeof(device_auth_tag));
    if (!hmac_sha256(kPqcSenderAuthKey, sizeof(kPqcSenderAuthKey),
                     reinterpret_cast<const uint8_t *>(&g_data_msg), auth_input_len,
                     device_auth_tag)) {
        printf("[sender] device HMAC generation failed\r\n");
        splunk_send_event("DEVICE_AUTH_FAIL", "high", "hmac_generation_failed");
        secure_zero(device_auth_tag, sizeof(device_auth_tag));
        return false;
    }
    memcpy(g_data_msg.buf + sizeof(g_kem_ct) + pt_len + sizeof(tag),
           device_auth_tag, sizeof(device_auth_tag));
    secure_zero(device_auth_tag, sizeof(device_auth_tag));

    const size_t payload_len = auth_input_len + PQC_DEVICE_AUTH_TAG_LEN;
    const uint16_t msg_id    = next_msg_id();
    const size_t coap_len = coap_build_post(g_coap_buf, sizeof(g_coap_buf),
                                             msg_id, "pqkem-data",
                                             reinterpret_cast<const uint8_t *>(&g_data_msg),
                                             payload_len);
    printf("[BENCH] path=pqc profile=AES-256-CCM+HMAC-SHA256 kem_ms=%lu hkdf_ms=%lu aead_ms=%lu plaintext_len=%u protected_payload_len=%u coap_wire_len=%u\r\n",
           (unsigned long)kem_ms,
           (unsigned long)hkdf_ms,
           (unsigned long)aead_ms,
           (unsigned)pt_len,
           (unsigned)payload_len,
           (unsigned)coap_len);
    if (coap_len == 0u) {
        printf("[sender] Failed to build /pqkem-data CoAP packet\r\n");
        secure_zero(&g_data_msg, sizeof(g_data_msg));
        return false;
    }

    uint8_t ack_input[PQC_ACK_INPUT_LEN], expected_ack[32];
    pqc_ack_input(ack_input,reinterpret_cast<const uint8_t *>(&g_data_msg)+auth_input_len);
    if(!hmac_sha256(kPqcSenderAuthKey,sizeof(kPqcSenderAuthKey),ack_input,sizeof(ack_input),expected_ack))return false;
    const uint32_t send_started=monotonic_ms();
    /* Step 9 — Send with retry */
    for (uint8_t attempt = 1; attempt <= MAX_DATA_RETRIES; ++attempt) {
        if (sendto(sock_fd, g_coap_buf, coap_len, 0,
                   reinterpret_cast<const struct sockaddr *>(gw),
                   sizeof(*gw)) < 0) {
            printf("[sender] sendto(/pqkem-data) failed errno=%d\r\n", errno);
            splunk_send_event("MSG_RETRY", "medium", "send_error");
            vTaskDelay(pdMS_TO_TICKS(300 * attempt));
            continue;
        }

        CoapMessage cm;
        if (!recv_coap_response(sock_fd, gw, "pqkem-data", msg_id, 6, &cm, NULL)) {
            printf("[sender] No ACK for data attempt %u/%u\r\n",
                   (unsigned)attempt, (unsigned)MAX_DATA_RETRIES);
            splunk_send_event("MSG_RETRY", "medium", "ack_timeout");
            vTaskDelay(pdMS_TO_TICKS(300 * attempt));
            continue;
        }

        printf("[sender] Gateway ACK code=0x%02X\r\n", (unsigned)cm.code);

        uint8_t ack_diff=0;
        if(cm.payload_len==sizeof(expected_ack)) for(size_t i=0;i<sizeof(expected_ack);i++)ack_diff|=cm.payload[i]^expected_ack[i];
        else ack_diff=1;
        if (cm.code == COAP_CODE_CHANGED && ack_diff==0) {
            printf("[BENCH] path=pqc sender_id=%lu generation=%lu sequence=%lu rtt_ms=%lu attempts=%u ok=1\r\n",
                (unsigned long)state->sender_id,(unsigned long)g_data_msg.generation,(unsigned long)g_data_msg.sequence,
                (unsigned long)(monotonic_ms()-send_started),(unsigned)attempt);
            printf("[sender] *** Message delivered and ACK received ***\r\n");
            splunk_send_event("MSG_DELIVERED", "info", "message_delivered");
            secure_zero(&g_data_msg, sizeof(g_data_msg));
            return true;
        }

        if(cm.code==COAP_CODE_CHANGED) { splunk_send_event("ACK_AUTH_FAIL","high","invalid_ack"); continue; }

        if (cm.payload && cm.payload_len > 0u)
            printf("[sender] Rejection: %.*s\r\n",
                   (int)cm.payload_len,
                   reinterpret_cast<const char *>(cm.payload));

        splunk_send_event("SEND_FAILED", "high", "gateway_rejected");
        secure_zero(&g_data_msg, sizeof(g_data_msg));
        return false;
    }

    splunk_send_event("SEND_FAILED", "high", "cycle_failed");
    secure_zero(&g_data_msg, sizeof(g_data_msg));
    return false;
}

/* ── Main sender task ─────────────────────────────────────────────── */

static void task_sender(void *param)
{
    (void)param;
    printf("[sender] Task started (ML-KEM-%u, level %u)\r\n",
           (unsigned)PQKEM_VARIANT, (unsigned)PQKEM_STRENGTH_LEVEL);
    printf("[CRYPTO] profile=%s key_bits=%u protocol_version=%u\r\n",
           PQC_CRYPTO_PROFILE,
           (unsigned)PQC_AEAD_KEY_BITS,
           (unsigned)PQC_PROTOCOL_VERSION);
    if (!pqc_sender_auth_key_is_provisioned() || !PQC_CREDENTIAL_GENERATION) {
        printf("[sender] FATAL: per-device authentication key is not provisioned\r\n");
        splunk_send_event("DEVICE_AUTH_KEY_MISSING", "critical", "fail_closed");
        vTaskDelete(NULL);
        return;
    }
    splunk_send_event("DEVICE_AUTH_ACTIVE", "info", "hmac_sha256_sender_identity");

    SenderStateStore state;
    if (!sender_state_init_or_load(&state)) {
        printf("[sender] FATAL: unable to initialize sender state\r\n");
        vTaskDelete(NULL);
        return;
    }

    int sock_fd = -1;
    while (sock_fd < 0) {
        sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock_fd < 0) {
            printf("[sender] socket() failed errno=%d\r\n", errno);
            vTaskDelay(pdMS_TO_TICKS(1000));
        }
    }

    struct sockaddr_in gw;
    if (!resolve_gateway_address(sock_fd, state, &gw)) {
        printf("[sender] ERROR: unable to resolve gateway address\r\n");
        close(sock_fd);
        vTaskDelete(NULL);
        return;
    }

    char ip_str[16] = {0};
    inet_ntoa_r(gw.sin_addr, ip_str, sizeof(ip_str));
    printf("[sender] Using gateway IP: %s\r\n", ip_str);
    print_hex("[sender] Provisioned fingerprint",
              kProvisionedGatewayPkFingerprint, PQC_PK_FINGERPRINT_LEN);

    unsigned cycle = 0u;
    unsigned consecutive_failures = 0u;

    /* Loop forever — sends continuously until power-off */
    while (1) {
        cycle++;
        printf("[sender] ===== secure send cycle %u =====\r\n", cycle);

        if (send_protected_message(sock_fd, &state, &gw)) {
            consecutive_failures = 0u;
            led_on_ms(300);
        } else {
            consecutive_failures++;
            printf("[sender] Send failed (#%u consecutive)\r\n",
                   consecutive_failures);

            if (consecutive_failures >= 3u) {
                printf("[sender] 3 consecutive failures — refreshing gateway address\r\n");
                state.last_gateway_ip = 0u;
                /* Address cache is opportunistic; never overwrite the counter reservation. */
                if (resolve_gateway_address(sock_fd, state, &gw)) {
                    inet_ntoa_r(gw.sin_addr, ip_str, sizeof(ip_str));
                    printf("[sender] New gateway IP: %s\r\n", ip_str);
                }
                consecutive_failures = 0u;
            }
        }

        /* Wait before next cycle */
        vTaskDelay(pdMS_TO_TICKS(2000));
    }

    close(sock_fd);
    vTaskDelete(NULL);
}

static void wait_for_wifi_ready()
{
    while (!g_wifi_ready) vTaskDelay(pdMS_TO_TICKS(200));
}

static void task_pq_starter(void *param)
{
    (void)param;
    printf("[starter] Waiting for Wi-Fi...\r\n");
    wait_for_wifi_ready();
    printf("[starter] Wi-Fi ready — starting sender\r\n");
    printf("[Splunk-S] Structured serial events enabled; forward captures from the host over HTTPS\r\n");

    if (!init_msg_id_counter()) { vTaskDelete(NULL); return; }

    /* This first event also triggers Splunk HEC auto-discovery. */
    splunk_send_event("WIFI_CONNECTED", "info", "wifi_up");
    splunk_send_event("SERIAL_TELEMETRY_READY", "info", "json_events_enabled");
    splunk_send_event("CRYPTO_PROFILE_ACTIVE", "info", "mlkem512_hkdf_sha256_aes256_ccm_hmac_v4");

    BaseType_t rc = xTaskCreate(task_sender, "sender", 6144, NULL, 10, NULL);
    printf("[starter] xTaskCreate rc=%ld\r\n", (long)rc);
    vTaskDelete(NULL);
}

extern "C" void app_main(void)
{
    vInitializeBL602();
    led_init();

    printf("\r\n=== Sender: ML-KEM-%u + HKDF-SHA-256 + AES-256-CCM === %s %s ===\r\n",
           (unsigned)PQKEM_VARIANT, __DATE__, __TIME__);

    xTaskCreateStatic(task_wifi, "wifi", WIFI_STACK_SIZE, NULL,
                      16, wifi_stack, &wifi_task);
    tcpip_init(NULL, NULL);

    BaseType_t rc = xTaskCreate(task_pq_starter, "pqstart", 2048, NULL, 9, NULL);
    printf("[main] starter xTaskCreate rc=%ld\r\n", (long)rc);

    vTaskStartScheduler();
    printf("[main] vTaskStartScheduler returned unexpectedly\r\n");
    for (;;) vTaskDelay(pdMS_TO_TICKS(1000));
}

extern "C" int bfl_main(void)
{
    app_main();
    return 0;
}
