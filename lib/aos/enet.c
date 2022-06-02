#include <aos/enet.h>
#include <drivers/enet.h>
#include <aos/nameserver.h>
#include <aos/dispatcher_arch.h>

static nameservice_chan_t enet_chan = NULL;

#define ENET_CHAN (enet_chan ? SYS_ERR_OK : nameservice_lookup(ENET_DRIVER_NAME, &enet_chan))

static void udp_recv_handler(void *st, void *message, size_t bytes, void **response,
                                size_t *response_bytes, struct capref rx_cap,
                                struct capref *tx_cap) {
    if (!capref_is_null(rx_cap) || message == NULL || bytes < sizeof(struct enet_udp_endpoint) || response == NULL || response_bytes == NULL || tx_cap == NULL) return;

    *response = NULL;
    *response_bytes = 0;
    *tx_cap = NULL_CAP;

    struct enet_udp_endpoint *hdr = message;
    void *data = (void*)(hdr + 1);
    int data_len = bytes - sizeof(struct enet_udp_endpoint);

    udp_listener_t listener = st;
    listener(hdr->ip, hdr->port, data, data_len);
}

errval_t enet_udp_create_socket(uint16_t port, enet_udp_socket *socket, udp_listener_t listener) {
    if (socket == NULL || listener == NULL) return ERR_INVALID_ARGS;

    errval_t err = ENET_CHAN;
    if (err_is_fail(err)) return err;

    domainid_t pid = get_dispatcher_generic(curdispatcher())->domain_id;
    size_t name_len = 4 + 2 * sizeof(domainid_t);
    size_t bytes = sizeof(struct enet_udp_msg) + name_len;

    struct enet_udp_msg *msg = malloc(bytes);
    msg->type = create;
    msg->socket = port;

    char *name = (char*)(msg + 1);
    if (name_len != snprintf(name, name_len, "udp%08X", pid) + 1) { // Adapt snprintf for changed domainid_t size!!!
        free(msg);
        return ERR_INVALID_ARGS;
    }

    struct enet_udp_res *response;
    size_t response_bytes;
    nameservice_register(name, udp_recv_handler, listener);
    LISTEN_DURING_RPC_CALL(
        err = nameservice_rpc(enet_chan, msg, bytes, (void**)&response, &response_bytes, NULL_CAP, NULL_CAP);
    );
    nameservice_deregister(name);
    free(msg);

    if (response == NULL) return NIC_ERR_NOSYS;
    else if (response_bytes != sizeof(struct enet_udp_res)) {
        free(response);
        return NIC_ERR_NOSYS;
    } else if (err_is_fail(response->err) || (port && response->socket != port)) {
        free(response);
        return response->err;
    }

    *socket = response->socket;

    err = response->err;
    free(response);

    return err;
}

errval_t enet_udp_destroy_socket(enet_udp_socket socket) {
    if (socket == 0) return ERR_INVALID_ARGS;

    errval_t err = ENET_CHAN;
    if (err_is_fail(err)) return err;

    struct enet_udp_msg msg;
    msg.type = destroy;
    msg.socket = socket;

    struct enet_udp_res *response;
    size_t response_bytes;
    err = nameservice_rpc(enet_chan, &msg, sizeof(msg), (void**)&response, &response_bytes, NULL_CAP, NULL_CAP);

    if (response == NULL) return NIC_ERR_NOSYS;
    else if (response_bytes != sizeof(struct enet_udp_res)
                || err_is_fail(response->err)
                || response->socket != socket) {
        free(response);
        return NIC_ERR_NOSYS;
    }

    err = response->err;
    free(response);

    return err;
}

errval_t enet_udp_send(void *data, size_t bytes, ip_addr_t dst_ip, uint16_t dst_port, enet_udp_socket socket) {
    if (socket == 0) return ERR_INVALID_ARGS;

    errval_t err = ENET_CHAN;
    if (err_is_fail(err)) return err;

    size_t msg_len = bytes + sizeof(struct enet_udp_msg) + sizeof(struct enet_udp_endpoint);
    struct enet_udp_msg *msg = malloc(msg_len);
    msg->type = send;
    msg->socket = socket;
    struct enet_udp_endpoint *endpoint = (struct enet_udp_endpoint*)(msg + 1);
    endpoint->ip = dst_ip;
    endpoint->port = dst_port;
    char* msg_data = (char*)(endpoint + 1);
    memcpy(msg_data, data, bytes);

    struct enet_udp_res *response;
    size_t response_bytes;
    err = nameservice_rpc(enet_chan, msg, msg_len, (void**)&response, &response_bytes, NULL_CAP, NULL_CAP);
    free(msg);

    if (response == NULL) return NIC_ERR_NOSYS;
    else if (response_bytes != sizeof(struct enet_udp_res)
                || err_is_fail(response->err)
                || (response->socket != socket)) {
        free(response);
        return NIC_ERR_NOSYS;
    }

    err = response->err;
    free(response);

    return err;
}
