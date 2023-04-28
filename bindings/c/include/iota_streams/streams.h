#ifndef IOTA_STREAMS_H
#define IOTA_STREAMS_H

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

typedef enum Err {
  ERR_OK,
  ERR_NULL_ARGUMENT,
  ERR_BAD_ARGUMENT,
  ERR_OPERATION_FAILED,
} err_t;

extern char const *get_last_error();

typedef enum PermissionType {
    PERM_READ,
    PERM_WRITE,
} permission_type_t;

typedef struct Buffer {
    uint8_t const *ptr;
    size_t size;
    size_t cap;
} buffer_t;

extern void drop_buffer(buffer_t);

typedef struct Address address_t;
extern void drop_address(address_t const *);
extern address_t *address_from_string(char const *addr_str);

typedef struct MsgId msgid_t;

typedef struct Identifier identifier_t;
extern void drop_identifier(identifier_t const *);
typedef struct Permissioned permissioned_t;
extern err_t new_permissioned(permissioned_t const **permissioned, identifier_t const *identifier, permission_type_t permission_type);
extern void drop_permissioned(permissioned_t const *);

typedef struct PskId psk_id_t;
extern void drop_psk_id(psk_id_t const *);


typedef struct IdLists id_lists_t;
extern const id_lists_t *new_id_lists();
extern void push_user_to_id_lists(id_lists_t const *id_lists, permissioned_t const *permission);
extern void push_psk_to_id_lists(id_lists_t const *id_lists, psk_id_t const *id);
extern void remove_user_from_id_lists(id_lists_t const *id_lists, identifier_t const *id);
extern void remove_psk_from_id_lists(id_lists_t const *id_lists, psk_id_t const *id);
extern void drop_id_lists(id_lists_t const *);


typedef struct Payloads {
    buffer_t public_payload;
    buffer_t masked_payload;
} payloads_t;

extern void drop_payloads(payloads_t);

typedef enum MessageType {
    ANNOUNCEMENT_MSG = 0,
    BRANCH_ANNOUNCEMENT_MSG = 1,
    KEYLOAD_MSG = 2,
    SIGNED_PACKET_MSG = 3,
    TAGGED_PACKET_MSG = 4,
    SUBSCRIBE_MSG = 5,
    UNSUBSCRIBE_MSG = 6,
    UNKNOWN_MSG = 7,
} message_type_t;

typedef struct Message {
    message_type_t message_type;
    address_t const *address;
    identifier_t const *publisher;
    payloads_t payloads;
} message_t;

extern char const *message_type_as_str(message_type_t message_type);
extern void drop_message(message_t const *);

////////////
/// Transport
////////////
typedef struct Transport transport_t;
extern transport_t *transport_new();
extern void transport_drop(transport_t *);
#ifdef IOTA_STREAMS_CLIENT
extern transport_t *transport_client_new_from_url(char const *url);
#endif


typedef struct User user_t;

extern err_t new_user_with_seed(user_t **user, char const *seed, transport_t *transport);
extern err_t recover_user(user_t **user, char const *seed, transport_t *transport);
extern void drop_user(user_t *);

extern err_t import_user(user_t **user, buffer_t buffer, char const *password, transport_t *transport);
extern err_t export_user(buffer_t *buf, user_t const *user, char const *password);

extern err_t stream_address(address_t const **addr, user_t const *user);
extern err_t identifier(identifier_t const **id, user_t const *user);

// Announce
extern err_t create_stream(address_t const **addr, user_t *user, char const *base);
// Subscribe
extern err_t subscribe(address_t const **addr, user_t *user);
// Unsubscribe
extern err_t unsubscribe(address_t const **addr, user_t *user);
// New branch
extern err_t new_branch(address_t const **addr, user_t *user, char const *old_topic, char const *new_topic);
// Keyload
extern err_t update_permissions(address_t const **addr, user_t *user, char const *topic, id_lists_t const *idLists);

// Send
extern err_t send_message(address_t const **addr, user_t *user, char const *topic, uint8_t const *payload_ptr, size_t payload_size, uint8_t sign, uint8_t mask);
// Receive
extern err_t receive_message(message_t const **msg, user_t *user, address_t const *address);
// Fetch Next Message
extern err_t fetch_next_message(message_t const **msg, user_t *user);
// Fetch User Role from Message. If Message is a Keyload, and the user is an included subscriber, then this will return
// the type of permissions available. If the message is not a keyload, or if the user is not included at all, then the
// operation will fail
extern err_t user_role(permission_type_t const **user_role, user_t *user, message_t const *message);


/////////////
/// Utility
/////////////
extern void drop_str(char const *str);

extern char const *get_msgid_str(msgid_t const *msgid);

extern char const *get_address_inst_str(address_t const *address);
extern char const *get_address_id_str(address_t const *address);

extern char const *get_address_index_str(address_t const *address);

extern char const *get_identifier_str(identifier_t const *id);
extern char const *get_permissioned_str(permissioned_t const *id);


#endif //IOTA_STREAMS_H