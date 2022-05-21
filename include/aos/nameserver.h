/**
 * \file nameservice.h
 * \brief 
 */

#ifndef INCLUDE_NAMESERVICE_H_
#define INCLUDE_NAMESERVICE_H_

#include <aos/aos.h>

// XXX: is there a more elegant way to expose it only to aos lib and init?
enum nameservice_rpc_identifier {
    NAMESERVICE_REGISTER,             // [call] payload: name
                                      // [return] errval

    NAMESERVICE_REFILL_LMP_ENDPOINT,  // Deprecated


    NAMESERVICE_DEREGISTER,           // [call] payload: name
                                      // [return] errval
    NAMESERVICE_LOOKUP,               // [call] payload: name
                                      // [return] err / cap: zeroed urpc_frame, payload: pid
    NAMESERVICE_ENUMERATE,            // [call] none
                                      // [return] err / struct enumerate_reply_msg
    NAMESERVICE_RPC_COUNT
};

enum ns_notification_identifier {
    SERVER_BIND_LMP,
    SERVER_BIND_UMP,
    KILL_BY_PID,
};

struct ns_binding_notification {
    domainid_t pid;
    char name[0];
};

typedef void* nameservice_chan_t;

/**
 * @brief handler which is called when a message is received over the registered channel
 * @note  response will be freed outside if assigned
 */
typedef void(nameservice_receive_handler_t)(void *st, 
										    void *message, size_t bytes,
										    void **response, size_t *response_bytes,
                                            struct capref tx_cap, struct capref *rx_cap);

/**
 * @brief make an rpc call
 *
 * @param chan opaque handle of the channel
 * @param message pointer to the message
 * @param bytes size of the message in bytes
 * @param response the response message, should be freed outside
 * @param response_bytes the size of the response
 * @param tx_cap if not NULL_CAP, the capability to send
 * @param rx_cap if not NULL_CAP, the slot to receive the return capability
 * 
 * @return error value
 */
errval_t nameservice_rpc(nameservice_chan_t chan, void *message, size_t bytes, 
                         void **response, size_t *response_bytes,
                         struct capref tx_cap, struct capref rx_cap);



/**
 * @brief registers our selves as 'name'
 *
 * @param name  our name
 * @param recv_handler the message handler for messages received over this service
 * @param st  state passed to the receive handler
 *
 * @return SYS_ERR_OK
 */
errval_t nameservice_register(const char *name, 
	                              nameservice_receive_handler_t recv_handler,
	                              void *st);


/**
 * @brief deregisters the service 'name'
 *
 * @param the name to deregister
 * 
 * @return error value
 */
errval_t nameservice_deregister(const char *name);


/**
 * @brief lookup an endpoint and obtain an RPC channel to that
 *
 * @param name  name to lookup
 * @param chan  pointer to the chan representation to send messages to the service
 *
 * @return  SYS_ERR_OK on success, errval on failure
 */
errval_t nameservice_lookup(const char *name, nameservice_chan_t *chan);


/**
 * @brief enumerates all entries that match an query (prefix match)
 * 
 * @param query     the query
 * @param num 		number of entries in the result array
 * @param result	an array of entries, should be freed outside (each entry and the whole)
 */
errval_t nameservice_enumerate(char *query, size_t *num, char ***result);


#endif /* INCLUDE_AOS_AOS_NAMESERVICE_H_ */
