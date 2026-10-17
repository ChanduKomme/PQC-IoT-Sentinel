/*
 * BL602/lwIP server-side compatibility for Mbed TLS net_sockets.
 *
 * The BL602 SDK port provides mbedtls_net_connect(), send(), recv(), and
 * recv_timeout(), but some SDK revisions omit mbedtls_net_bind() and
 * mbedtls_net_accept().  The DTLS receiver needs those two functions.
 *
 * These definitions are weak: if a future SDK supplies strong versions,
 * the SDK implementations take precedence without creating a duplicate
 * symbol error.
 */

#include <string.h>

#include <lwip/netdb.h>
#include <lwip/sockets.h>

#include <mbedtls/net_sockets.h>

#if defined(__GNUC__)
#define PQC_DTLS_WEAK __attribute__((weak))
#else
#define PQC_DTLS_WEAK
#endif

static int pqc_dtls_socket_type(int proto)
{
    return proto == MBEDTLS_NET_PROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;
}

static int pqc_dtls_socket_protocol(int proto)
{
    return proto == MBEDTLS_NET_PROTO_UDP ? IPPROTO_UDP : IPPROTO_TCP;
}

PQC_DTLS_WEAK int mbedtls_net_bind(mbedtls_net_context *ctx,
                                   const char *bind_ip,
                                   const char *port,
                                   int proto)
{
    int ret = MBEDTLS_ERR_NET_UNKNOWN_HOST;
    struct addrinfo hints;
    struct addrinfo *addr_list = NULL;
    struct addrinfo *cur = NULL;

    if (ctx == NULL || port == NULL) {
        return MBEDTLS_ERR_NET_BAD_INPUT_DATA;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = pqc_dtls_socket_type(proto);
    hints.ai_protocol = pqc_dtls_socket_protocol(proto);
    if (bind_ip == NULL) {
        hints.ai_flags = AI_PASSIVE;
    }

    if (getaddrinfo(bind_ip, port, &hints, &addr_list) != 0) {
        return MBEDTLS_ERR_NET_UNKNOWN_HOST;
    }

    ret = MBEDTLS_ERR_NET_BIND_FAILED;
    for (cur = addr_list; cur != NULL; cur = cur->ai_next) {
        int reuse = 1;

        ctx->fd = socket(cur->ai_family,
                         cur->ai_socktype,
                         cur->ai_protocol);
        if (ctx->fd < 0) {
            ret = MBEDTLS_ERR_NET_SOCKET_FAILED;
            continue;
        }

        (void)setsockopt(ctx->fd,
                         SOL_SOCKET,
                         SO_REUSEADDR,
                         (const void *)&reuse,
                         (socklen_t)sizeof(reuse));

        if (bind(ctx->fd,
                 cur->ai_addr,
                 (socklen_t)cur->ai_addrlen) != 0) {
            mbedtls_net_close(ctx);
            ret = MBEDTLS_ERR_NET_BIND_FAILED;
            continue;
        }

        if (proto == MBEDTLS_NET_PROTO_TCP && listen(ctx->fd, 1) != 0) {
            mbedtls_net_close(ctx);
            ret = MBEDTLS_ERR_NET_LISTEN_FAILED;
            continue;
        }

        ret = 0;
        break;
    }

    freeaddrinfo(addr_list);
    return ret;
}

PQC_DTLS_WEAK int mbedtls_net_accept(mbedtls_net_context *bind_ctx,
                                     mbedtls_net_context *client_ctx,
                                     void *client_ip,
                                     size_t buf_size,
                                     size_t *client_ip_len)
{
    int socket_type = 0;
    socklen_t socket_type_len = (socklen_t)sizeof(socket_type);
    struct sockaddr_in peer_addr;
    socklen_t peer_len = (socklen_t)sizeof(peer_addr);
    int ret;

    if (bind_ctx == NULL || client_ctx == NULL || bind_ctx->fd < 0) {
        return MBEDTLS_ERR_NET_BAD_INPUT_DATA;
    }

    memset(&peer_addr, 0, sizeof(peer_addr));

    if (getsockopt(bind_ctx->fd,
                   SOL_SOCKET,
                   SO_TYPE,
                   (void *)&socket_type,
                   &socket_type_len) != 0) {
        return MBEDTLS_ERR_NET_ACCEPT_FAILED;
    }

    if (socket_type == SOCK_STREAM) {
        client_ctx->fd = accept(bind_ctx->fd,
                                (struct sockaddr *)&peer_addr,
                                &peer_len);
        if (client_ctx->fd < 0) {
            return MBEDTLS_ERR_NET_ACCEPT_FAILED;
        }
    } else if (socket_type == SOCK_DGRAM) {
        unsigned char first_byte = 0;
        struct sockaddr_in local_addr;
        socklen_t local_len = (socklen_t)sizeof(local_addr);
        int reuse = 1;

        /* Learn the peer without consuming the first DTLS datagram. */
        ret = recvfrom(bind_ctx->fd,
                       &first_byte,
                       sizeof(first_byte),
                       MSG_PEEK,
                       (struct sockaddr *)&peer_addr,
                       &peer_len);
        if (ret < 0) {
            return MBEDTLS_ERR_NET_ACCEPT_FAILED;
        }

        memset(&local_addr, 0, sizeof(local_addr));
        if (getsockname(bind_ctx->fd,
                        (struct sockaddr *)&local_addr,
                        &local_len) != 0) {
            return MBEDTLS_ERR_NET_SOCKET_FAILED;
        }

        /* Convert the original socket into a connected per-peer socket. */
        if (connect(bind_ctx->fd,
                    (struct sockaddr *)&peer_addr,
                    peer_len) != 0) {
            return MBEDTLS_ERR_NET_ACCEPT_FAILED;
        }

        client_ctx->fd = bind_ctx->fd;
        bind_ctx->fd = -1;

        /* Recreate the listening socket on the same local UDP port. */
        bind_ctx->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (bind_ctx->fd < 0) {
            return MBEDTLS_ERR_NET_SOCKET_FAILED;
        }

        (void)setsockopt(bind_ctx->fd,
                         SOL_SOCKET,
                         SO_REUSEADDR,
                         (const void *)&reuse,
                         (socklen_t)sizeof(reuse));

        if (bind(bind_ctx->fd,
                 (struct sockaddr *)&local_addr,
                 local_len) != 0) {
            mbedtls_net_close(bind_ctx);
            return MBEDTLS_ERR_NET_BIND_FAILED;
        }
    } else {
        return MBEDTLS_ERR_NET_ACCEPT_FAILED;
    }

    if (client_ip != NULL && client_ip_len != NULL) {
        const size_t id_len = sizeof(peer_addr.sin_addr.s_addr) +
                              sizeof(peer_addr.sin_port);
        if (buf_size < id_len) {
            mbedtls_net_free(client_ctx);
            return MBEDTLS_ERR_NET_BUFFER_TOO_SMALL;
        }

        memcpy(client_ip,
               &peer_addr.sin_addr.s_addr,
               sizeof(peer_addr.sin_addr.s_addr));
        memcpy((unsigned char *)client_ip + sizeof(peer_addr.sin_addr.s_addr),
               &peer_addr.sin_port,
               sizeof(peer_addr.sin_port));
        *client_ip_len = id_len;
    }

    return 0;
}
