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
    #include <mbedtls/pk.h>
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

static int handshake_server(mbedtls_ssl_context *ssl)
{
    int rc;
    do {
        rc = mbedtls_ssl_handshake(ssl);
    } while (rc == MBEDTLS_ERR_SSL_WANT_READ ||
             rc == MBEDTLS_ERR_SSL_WANT_WRITE);
    return rc;
}

static void task_dtls_receiver(void *param)
{
    (void)param;
    while (!g_wifi_ready) {
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    int rc = 0;
    mbedtls_net_context listen_fd;
    mbedtls_net_context client_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt server_cert;
    mbedtls_pk_context server_key;
    mbedtls_timing_delay_context timer;

    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&server_cert);
    mbedtls_pk_init(&server_key);
    memset(&timer, 0, sizeof(timer));

    static const char personalization[] = "pqc-iot-dtls-baseline-server";
    static const int ciphersuites[] = {
        DTLS_BASELINE_CIPHERSUITE,
        0
    };
    static const PqcDtlsGroup groups[] = {
        PQC_DTLS_P256,
        PQC_DTLS_GROUP_NONE
    };

    rc = mbedtls_ctr_drbg_seed(&ctr_drbg,
                               mbedtls_entropy_func,
                               &entropy,
                               reinterpret_cast<const unsigned char *>(personalization),
                               sizeof(personalization) - 1u);
    if (rc != 0) {
        print_mbedtls_error("ctr_drbg_seed", rc);
        goto fatal;
    }

    rc = mbedtls_x509_crt_parse(&server_cert,
                                reinterpret_cast<const unsigned char *>(kDtlsServerCertPem),
                                sizeof(kDtlsServerCertPem));
    if (rc < 0) {
        print_mbedtls_error("x509_crt_parse(server)", rc);
        goto fatal;
    }

    rc = pqc_dtls_parse_key(&server_key, reinterpret_cast<const unsigned char *>(kDtlsServerKeyPem), sizeof(kDtlsServerKeyPem), &ctr_drbg);
    if (rc != 0) {
        print_mbedtls_error("pk_parse_key", rc);
        goto fatal;
    }

    rc = mbedtls_net_bind(&listen_fd,
                          "0.0.0.0",
                          DTLS_SERVER_PORT,
                          MBEDTLS_NET_PROTO_UDP);
    if (rc != 0) {
        print_mbedtls_error("net_bind", rc);
        goto fatal;
    }

    rc = mbedtls_ssl_config_defaults(&conf,
                                     MBEDTLS_SSL_IS_SERVER,
                                     MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT);
    if (rc != 0) {
        print_mbedtls_error("ssl_config_defaults", rc);
        goto fatal;
    }

    pqc_dtls_tls12(&conf);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_read_timeout(&conf, DTLS_READ_TIMEOUT_MS);
    mbedtls_ssl_conf_ciphersuites(&conf, ciphersuites);
    pqc_dtls_groups(&conf, groups);

    /*
     * mbedtls_ssl_config_defaults() installs dummy DTLS cookie callbacks
     * when MBEDTLS_SSL_DTLS_HELLO_VERIFY is enabled. Those callbacks return
     * MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE unless ssl_cookie.c is linked.
     * This isolated benchmark explicitly disables HelloVerifyRequest cookies.
     */
    mbedtls_ssl_conf_dtls_cookies(&conf, NULL, NULL, NULL);

    rc = mbedtls_ssl_conf_own_cert(&conf, &server_cert, &server_key);
    if (rc != 0) {
        print_mbedtls_error("ssl_conf_own_cert", rc);
        goto fatal;
    }

    /*
     * The default BL602 Mbed TLS component does not link ssl_cookie.c.
     * This laboratory baseline therefore omits HelloVerifyRequest cookies
     * and relies on the authenticated DTLS handshake plus a connected UDP
     * peer socket. Enable the SDK cookie module before production use.
     */

    rc = mbedtls_ssl_setup(&ssl, &conf);
    if (rc != 0) {
        print_mbedtls_error("ssl_setup", rc);
        goto fatal;
    }
    mbedtls_ssl_set_timer_cb(&ssl,
                             &timer,
                             mbedtls_timing_set_delay,
                             mbedtls_timing_get_delay);

    printf("[DTLS] receiver listening udp/%s profile=%s\r\n",
           DTLS_SERVER_PORT,
           DTLS_BASELINE_PROFILE);

    while (1) {
        unsigned char client_ip[16] = {0};
        size_t client_ip_len = 0u;
        mbedtls_net_free(&client_fd);
        mbedtls_ssl_session_reset(&ssl);

        printf("[DTLS] waiting_for_client=1\r\n");
        rc = mbedtls_net_accept(&listen_fd,
                                &client_fd,
                                client_ip,
                                sizeof(client_ip),
                                &client_ip_len);
        if (rc != 0) {
            print_mbedtls_error("net_accept", rc);
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        rc = mbedtls_ssl_set_client_transport_id(&ssl,
                                                 client_ip,
                                                 client_ip_len);
        if (rc != 0) {
            print_mbedtls_error("ssl_set_client_transport_id", rc);
            continue;
        }

        mbedtls_ssl_set_bio(&ssl,
                            &client_fd,
                            mbedtls_net_send,
                            mbedtls_net_recv,
                            mbedtls_net_recv_timeout);

        const uint32_t handshake_t0 = monotonic_ms();
        rc = handshake_server(&ssl);
        const uint32_t handshake_ms = monotonic_ms() - handshake_t0;

        if (rc != 0) {
            print_mbedtls_error("ssl_handshake", rc);
            continue;
        }

        const char *cipher = mbedtls_ssl_get_ciphersuite(&ssl);
        const char *version = mbedtls_ssl_get_version(&ssl);
        const int expansion = mbedtls_ssl_get_record_expansion(&ssl);
        printf("[DTLS_HANDSHAKE] role=receiver success=1 handshake_ms=%lu version=%s cipher=%s record_expansion=%d\r\n",
               (unsigned long)handshake_ms,
               version ? version : "unknown",
               cipher ? cipher : "unknown",
               expansion);

        unsigned run = 0u;
        while (1) {
            uint8_t request[DTLS_MAX_RECORD];
            uint8_t response[DTLS_MAX_RECORD];
            memset(request, 0, sizeof(request));

            do {
                rc = mbedtls_ssl_read(&ssl, request, sizeof(request));
            } while (rc == MBEDTLS_ERR_SSL_WANT_READ ||
                     rc == MBEDTLS_ERR_SSL_WANT_WRITE);

            if (rc == MBEDTLS_ERR_SSL_TIMEOUT) {
                printf("[DTLS] idle_timeout=1\r\n");
                break;
            }
            if (rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || rc == 0) {
                printf("[DTLS] peer_closed=1\r\n");
                break;
            }
            if (rc < 0) {
                print_mbedtls_error("ssl_read", rc);
                break;
            }

            run++;
            const uint32_t process_t0 = monotonic_ms();
            CoapMessage parsed;
            const bool valid = coap_parse(&parsed, request, (size_t)rc) &&
                               parsed.ver == 1u &&
                               parsed.type == COAP_TYPE_CON &&
                               parsed.code == COAP_CODE_POST &&
                               strcmp(parsed.uri_path, DTLS_COAP_URI) == 0 &&
                               parsed.payload_len == DTLS_PAYLOAD_LEN &&
                               memcmp(parsed.payload, DTLS_PAYLOAD, DTLS_PAYLOAD_LEN) == 0;

            static const uint8_t ok_text[] = "OK";
            static const uint8_t bad_text[] = "BAD_REQUEST";
            const uint8_t response_code = valid ? COAP_CODE_CHANGED : 0x80u;
            const uint8_t *response_payload = valid ? ok_text : bad_text;
            const size_t response_payload_len = valid
                                              ? sizeof(ok_text) - 1u
                                              : sizeof(bad_text) - 1u;
            const uint16_t response_msg_id = valid ? parsed.msg_id : 0u;
            const size_t response_len = coap_build_simple(response,
                                                          sizeof(response),
                                                          COAP_TYPE_ACK,
                                                          response_code,
                                                          response_msg_id,
                                                          DTLS_COAP_URI,
                                                          response_payload,
                                                          response_payload_len);
            const uint32_t process_ms = monotonic_ms() - process_t0;

            if (response_len == 0u) {
                printf("[DTLS_BENCH] role=receiver run=%u success=0 error=coap_build\r\n", run);
                continue;
            }

            const int write_rc = ssl_write_all(&ssl, response, response_len);
            if (write_rc < 0) {
                print_mbedtls_error("ssl_write", write_rc);
                break;
            }

            printf("[DTLS_BENCH] role=receiver run=%u success=%u handshake_ms=%lu process_ms=%lu app_payload_len=%u coap_len=%u\r\n",
                   run,
                   valid ? 1u : 0u,
                   (unsigned long)handshake_ms,
                   (unsigned long)process_ms,
                   valid ? (unsigned)parsed.payload_len : 0u,
                   (unsigned)rc);
        }

        do {
            rc = mbedtls_ssl_close_notify(&ssl);
        } while (rc == MBEDTLS_ERR_SSL_WANT_WRITE);
    }

fatal:
    mbedtls_net_free(&client_fd);
    mbedtls_net_free(&listen_fd);
    mbedtls_pk_free(&server_key);
    mbedtls_x509_crt_free(&server_cert);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    printf("[DTLS] receiver task stopped rc=%d\r\n", rc);
    vTaskDelete(NULL);
}

extern "C" void app_main(void)
{
    vInitializeBL602();
    printf("\r\n=== DTLS receiver baseline: %s === %s %s ===\r\n",
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

    BaseType_t rc = xTaskCreate(task_dtls_receiver,
                                "dtls_receiver",
                                16384,
                                NULL,
                                10,
                                NULL);
    printf("[main] dtls receiver task rc=%ld\r\n", (long)rc);

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
