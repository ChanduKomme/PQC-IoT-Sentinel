extern "C" {
    void vInitializeBL602(void);

    #include <FreeRTOS.h>
    #include <task.h>
    #include <stdio.h>
    #include <stdint.h>
    #include <string.h>
    #include <lwip/tcpip.h>

    #include <mbedtls/ctr_drbg.h>
    #include <mbedtls/entropy.h>
    #include <mbedtls/error.h>
    #include <mbedtls/net_sockets.h>
    #include <mbedtls/ssl.h>
    #include <mbedtls/timing.h>
    #include <mbedtls/x509_crt.h>
}

#include "coap_minimal.h"
#include "dtls_baseline_config.h"
#include "../../common/mbedtls_compat.h"
#include "dtls_dev_credentials.h"

extern "C" void task_wifi(void *param);
extern "C" volatile uint8_t g_wifi_ready;

#define WIFI_STACK_SIZE 512
static StackType_t wifi_stack[WIFI_STACK_SIZE];
static StaticTask_t wifi_task;

static uint32_t monotonic_ms(void)
{
    return (uint32_t)xTaskGetTickCount() * (uint32_t)portTICK_PERIOD_MS;
}

static void print_mbedtls_error(const char *where, int rc)
{
    char text[160] = {0};
    mbedtls_strerror(rc, text, sizeof(text));
    printf("[DTLS] %s failed rc=-0x%04X (%s)\r\n",
           where,
           (unsigned)(-rc),
           text);
}

static int ssl_write_all(mbedtls_ssl_context *ssl,
                         const uint8_t *buf,
                         size_t len)
{
    size_t offset = 0u;
    while (offset < len) {
        int rc = mbedtls_ssl_write(ssl, buf + offset, len - offset);
        if (rc == MBEDTLS_ERR_SSL_WANT_READ ||
            rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        if (rc <= 0) {
            return rc;
        }
        offset += (size_t)rc;
    }
    return (int)offset;
}

static int ssl_read_record(mbedtls_ssl_context *ssl,
                           uint8_t *buf,
                           size_t capacity)
{
    while (1) {
        int rc = mbedtls_ssl_read(ssl, buf, capacity);
        if (rc == MBEDTLS_ERR_SSL_WANT_READ ||
            rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        return rc;
    }
}

static bool run_dtls_baseline(void)
{
    int rc = 0;
    bool ok = false;
    mbedtls_net_context server_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt ca;
    mbedtls_timing_delay_context timer;

    mbedtls_net_init(&server_fd);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&ca);
    memset(&timer, 0, sizeof(timer));

    static const char personalization[] = "pqc-iot-dtls-baseline-client";
    static const int ciphersuites[] = {
        DTLS_BASELINE_CIPHERSUITE,
        0
    };
    static const PqcDtlsGroup groups[] = {
        PQC_DTLS_P256,
        PQC_DTLS_GROUP_NONE
    };

    do {
        rc = mbedtls_ctr_drbg_seed(&ctr_drbg,
                                   mbedtls_entropy_func,
                                   &entropy,
                                   reinterpret_cast<const unsigned char *>(personalization),
                                   sizeof(personalization) - 1u);
        if (rc != 0) {
            print_mbedtls_error("ctr_drbg_seed", rc);
            break;
        }

        rc = mbedtls_x509_crt_parse(&ca,
                                    reinterpret_cast<const unsigned char *>(kDtlsCaCertPem),
                                    sizeof(kDtlsCaCertPem));
        if (rc < 0) {
            print_mbedtls_error("x509_crt_parse(CA)", rc);
            break;
        }

        printf("[DTLS] connecting host=%s port=%s profile=%s\r\n",
               DTLS_SERVER_HOST,
               DTLS_SERVER_PORT,
               DTLS_BASELINE_PROFILE);
        rc = mbedtls_net_connect(&server_fd,
                                 DTLS_SERVER_HOST,
                                 DTLS_SERVER_PORT,
                                 MBEDTLS_NET_PROTO_UDP);
        if (rc != 0) {
            print_mbedtls_error("net_connect", rc);
            break;
        }

        rc = mbedtls_ssl_config_defaults(&conf,
                                         MBEDTLS_SSL_IS_CLIENT,
                                         MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT);
        if (rc != 0) {
            print_mbedtls_error("ssl_config_defaults", rc);
            break;
        }

        pqc_dtls_tls12(&conf);
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_ca_chain(&conf, &ca, NULL);
        mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
        mbedtls_ssl_conf_read_timeout(&conf, DTLS_READ_TIMEOUT_MS);
        mbedtls_ssl_conf_ciphersuites(&conf, ciphersuites);
        pqc_dtls_groups(&conf, groups);

        rc = mbedtls_ssl_setup(&ssl, &conf);
        if (rc != 0) {
            print_mbedtls_error("ssl_setup", rc);
            break;
        }

        rc = mbedtls_ssl_set_hostname(&ssl, DTLS_SERVER_NAME);
        if (rc != 0) {
            print_mbedtls_error("ssl_set_hostname", rc);
            break;
        }

        mbedtls_ssl_set_bio(&ssl,
                            &server_fd,
                            mbedtls_net_send,
                            mbedtls_net_recv,
                            mbedtls_net_recv_timeout);
        mbedtls_ssl_set_timer_cb(&ssl,
                                 &timer,
                                 mbedtls_timing_set_delay,
                                 mbedtls_timing_get_delay);

        const uint32_t handshake_t0 = monotonic_ms();
        do {
            rc = mbedtls_ssl_handshake(&ssl);
        } while (rc == MBEDTLS_ERR_SSL_WANT_READ ||
                 rc == MBEDTLS_ERR_SSL_WANT_WRITE);
        const uint32_t handshake_ms = monotonic_ms() - handshake_t0;

        if (rc != 0) {
            print_mbedtls_error("ssl_handshake", rc);
            break;
        }

        const uint32_t verify_flags = mbedtls_ssl_get_verify_result(&ssl);
        if (verify_flags != 0u) {
            printf("[DTLS] certificate verification failed flags=0x%08lX\r\n",
                   (unsigned long)verify_flags);
            break;
        }

        const char *cipher = mbedtls_ssl_get_ciphersuite(&ssl);
        const char *version = mbedtls_ssl_get_version(&ssl);
        const int expansion = mbedtls_ssl_get_record_expansion(&ssl);
        printf("[DTLS_HANDSHAKE] role=sender success=1 handshake_ms=%lu version=%s cipher=%s record_expansion=%d\r\n",
               (unsigned long)handshake_ms,
               version ? version : "unknown",
               cipher ? cipher : "unknown",
               expansion);

        uint8_t request[DTLS_MAX_RECORD];
        uint8_t response[DTLS_MAX_RECORD];
        uint16_t msg_id = (uint16_t)(monotonic_ms() & 0xFFFFu);
        unsigned success_count = 0u;
        unsigned attempted_count = 0u;

        for (unsigned run = 1u; run <= DTLS_SAMPLE_COUNT; ++run) {
            attempted_count++;
            msg_id++;
            const size_t request_len = coap_build_simple(request,
                                                         sizeof(request),
                                                         COAP_TYPE_CON,
                                                         COAP_CODE_POST,
                                                         msg_id,
                                                         DTLS_COAP_URI,
                                                         reinterpret_cast<const uint8_t *>(DTLS_PAYLOAD),
                                                         DTLS_PAYLOAD_LEN);
            if (request_len == 0u) {
                printf("[DTLS_BENCH] role=sender run=%u success=0 error=coap_build\r\n", run);
                continue;
            }

            const uint32_t rtt_t0 = monotonic_ms();
            rc = ssl_write_all(&ssl, request, request_len);
            if (rc < 0) {
                print_mbedtls_error("ssl_write", rc);
                printf("[DTLS_BENCH] role=sender run=%u success=0 error=ssl_write\r\n", run);
                break;
            }

            memset(response, 0, sizeof(response));
            rc = ssl_read_record(&ssl, response, sizeof(response));
            const uint32_t rtt_ms = monotonic_ms() - rtt_t0;
            if (rc <= 0) {
                if (rc < 0) {
                    print_mbedtls_error("ssl_read", rc);
                }
                printf("[DTLS_BENCH] role=sender run=%u success=0 rtt_ms=%lu error=ssl_read\r\n",
                       run,
                       (unsigned long)rtt_ms);
                break;
            }

            CoapMessage parsed;
            const bool valid = coap_parse(&parsed, response, (size_t)rc) &&
                               parsed.type == COAP_TYPE_ACK &&
                               parsed.code == COAP_CODE_CHANGED &&
                               parsed.msg_id == msg_id &&
                               parsed.payload_len == 2u &&
                               memcmp(parsed.payload, "OK", 2u) == 0;

            if (valid) {
                success_count++;
            }

            const int estimated_record_len = expansion >= 0
                                           ? (int)request_len + expansion
                                           : -1;
            printf("[DTLS_BENCH] role=sender run=%u success=%u handshake_ms=%lu rtt_ms=%lu app_payload_len=%u coap_len=%u estimated_dtls_record_len=%d\r\n",
                   run,
                   valid ? 1u : 0u,
                   (unsigned long)handshake_ms,
                   (unsigned long)rtt_ms,
                   (unsigned)DTLS_PAYLOAD_LEN,
                   (unsigned)request_len,
                   estimated_record_len);

            vTaskDelay(pdMS_TO_TICKS(DTLS_INTER_MESSAGE_DELAY_MS));
        }

        printf("[DTLS_SUMMARY] role=sender requested=%u attempted=%u succeeded=%u failed=%u profile=%s\r\n",
               (unsigned)DTLS_SAMPLE_COUNT,
               attempted_count,
               success_count,
               attempted_count - success_count,
               DTLS_BASELINE_PROFILE);

        do {
            rc = mbedtls_ssl_close_notify(&ssl);
        } while (rc == MBEDTLS_ERR_SSL_WANT_WRITE);
        ok = success_count == DTLS_SAMPLE_COUNT;
    } while (false);

    mbedtls_x509_crt_free(&ca);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_net_free(&server_fd);
    return ok;
}

static void task_dtls_sender(void *param)
{
    (void)param;
    while (!g_wifi_ready) {
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    printf("[DTLS] Wi-Fi ready; starting same-board baseline\r\n");
    unsigned session=0;
    while (1) {
        printf("[DTLS_SESSION] role=sender session=%u\r\n",++session);
        const bool ok = run_dtls_baseline();
        printf("[DTLS] baseline_session_complete success=%u\r\n", ok ? 1u : 0u);
        if(!DTLS_REPEAT_SESSIONS) { vTaskDelete(NULL); return; }
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}

extern "C" void app_main(void)
{
    vInitializeBL602();
    printf("\r\n=== DTLS sender baseline: %s === %s %s ===\r\n",
           DTLS_BASELINE_PROFILE,
           __DATE__,
           __TIME__);

    xTaskCreateStatic(task_wifi,
                      "wifi",
                      WIFI_STACK_SIZE,
                      NULL,
                      16,
                      wifi_stack,
                      &wifi_task);
    tcpip_init(NULL, NULL);

    BaseType_t rc = xTaskCreate(task_dtls_sender,
                                "dtls_sender",
                                12288,
                                NULL,
                                10,
                                NULL);
    printf("[main] dtls sender task rc=%ld\r\n", (long)rc);

    vTaskStartScheduler();
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

extern "C" int bfl_main(void)
{
    app_main();
    return 0;
}
