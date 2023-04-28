#include "iota_streams/streams.h"
#include <stdio.h>
#include <time.h>
#include <assert.h>

void rand_seed(char *seed, size_t n)
{
  static char const alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-=_+";
  srand((unsigned int)time(NULL));

  if (seed && n)
  for(; --n; )
  {
    int key = rand() % (sizeof(alphabet) - 1);
    *seed++ = alphabet[key];
  }
  *seed = '\0';
}

int main() {
    err_t e = ERR_OK;

    transport_t *tsp = NULL;

    char const base_branch[] = "Base Branch Topic";
    char const subA_topic[] = "Sub A Topic";
    char const data_payload[] = "Arbitrary payload";

    user_t *auth = NULL;
    address_t const *ann_link = NULL;
    user_t *subA = NULL;
    user_t *subB = NULL;
    user_t *subC = NULL;
    identifier_t const *auth_id = NULL;
    identifier_t const *subA_id = NULL;
    identifier_t const *subB_id = NULL;
    identifier_t const *subC_id = NULL;


    printf("Starting c bindings test\n\n");
    // Replace with unique seed if desired
    char seed[] = "bindings test seed";
    // Comment out this line if using a unique seed
    rand_seed(seed, sizeof(seed));

#ifdef IOTA_STREAMS_CLIENT
    char const *env_url = getenv("URL");
    char const *url = env_url ? env_url : "http://chrysalis-nodes.iota.org";

    printf("Using node: %s\n\n", url);
    tsp = transport_client_new_from_url(url);
#else
    printf("Using bucket transport (offline) \n\n");
    tsp = transport_new();
#endif
    printf("Making author with seed '%s'... ", seed);
    e = new_user_with_seed(&auth, seed, tsp);
    printf("%s\n", !e ? "done" : "failed");
    if (e) goto cleanup;

    // Fetch Application instance
    {
        printf("Fetching Author Id\n");
        e = identifier(&auth_id, auth);
        if (e) goto cleanup;
        char const *auth_id_str = get_identifier_str(auth_id);
        printf("Author id: '%s'\n", auth_id_str);
        drop_str(auth_id_str);
    }
    printf("\n");

    // Announcement
    {

        printf("Sending announcement... ");
        e = create_stream(&ann_link, auth, base_branch);
        printf("%s\n", !e ? "done" : "failed");
        if (e) goto cleanup;

        {
            char const *ann_address_inst_str = NULL;
            char const *ann_address_id_str = NULL;
            address_t *ann_link_copy = NULL;
            char const *ann_cpy_inst_str = NULL;
            char const *ann_cpy_id_str = NULL;
            char const *link_index = NULL;

            // Test conversions
            printf("Converting announcement link to string... \n");
            ann_address_inst_str = get_address_inst_str(ann_link);
            ann_address_id_str = get_address_id_str(ann_link);
            // printf("  appinst: '%s'\n", ann_address_inst_str);
            // printf("  msgid  : '%s'\n", ann_address_id_str);

            char const connector[] = ":";
            char buffer[200];
            assert(strlen(ann_address_inst_str) + strlen(ann_address_id_str) + 1 <= sizeof(buffer));
            buffer[0] = '\0';
            strcat(buffer, ann_address_inst_str);
            strcat(buffer, connector);
            strcat(buffer, ann_address_id_str);
            printf("  '%s'\n", buffer);

            printf("Creating copy address from address string\n");
            ann_link_copy = address_from_string(buffer);
            ann_cpy_inst_str = get_address_inst_str(ann_link_copy);
            ann_cpy_id_str = get_address_id_str(ann_link_copy);

            printf("Comparing copy address and original... ");
            if (0
                || 0 != strcmp(ann_address_inst_str, ann_cpy_inst_str)
                || 0 != strcmp(ann_address_id_str, ann_cpy_id_str)
                    ) {
                e = ERR_OPERATION_FAILED;
                printf("failed\n");
                goto cleanup0;
            }
            printf("done\n");

            printf("Converting announcement link to tangle index... \n");
            link_index = get_address_index_str(ann_link_copy);
            printf("  '%s'\n", link_index);

            cleanup0:
            drop_str(link_index);
            drop_str(ann_cpy_id_str);
            drop_str(ann_cpy_inst_str);
            drop_address(ann_link_copy);
            drop_str(ann_address_id_str);
            drop_str(ann_address_inst_str);
        }
        printf("\n");

        // Subscribing
        {
            address_t const *sub_a_link = NULL;
            address_t const *sub_b_link = NULL;
            address_t const *sub_c_link = NULL;
            message_t const *received_announcement = NULL;
            char const sub_a_seed[] = "SubA";
            char const sub_b_seed[] = "SubB";
            char const sub_c_seed[] = "SubC";
            char const *sub_inst_str = NULL;
            char const *sub_id_str = NULL;

            printf("Making subscribers...\n");
            printf("\tSubA...");
            e = new_user_with_seed(&subA, sub_a_seed, tsp);
            printf("%s\n", !e ? "done" : "failed");
            if (e) goto cleanup1;

            printf("\tSubB...");
            e = new_user_with_seed(&subB, sub_b_seed, tsp);
            printf("%s\n", !e ? "done" : "failed");
            if (e) goto cleanup1;

            printf("\tSubC...");
            e = new_user_with_seed(&subC, sub_c_seed, tsp);
            printf("%s\n", !e ? "done" : "failed");
            if (e) goto cleanup1;

            printf("Receiving announcement message...\n");
            printf("\tSubA...");
            e = receive_message(&received_announcement, subA, ann_link);
            printf("%s\n", !e ? "done" : "failed");
            if (e) goto cleanup1;

            printf("\tSubB...");
            e = receive_message(&received_announcement, subB, ann_link);
            printf("%s\n", !e ? "done" : "failed");
            if (e) goto cleanup1;

            printf("\tSubC...");
            e = receive_message(&received_announcement, subC, ann_link);
            printf("%s\n", !e ? "done" : "failed");
            if (e) goto cleanup1;


            printf("Sending subscription messages...\n");
            printf("\tSubA...");
            e = subscribe(&sub_a_link, subA);
            printf("%s\n", !e ? "done" : "failed");
            if (e) goto cleanup1;
            sub_inst_str = get_address_inst_str(sub_a_link);
            sub_id_str = get_address_id_str(sub_a_link);
            printf("\t\t%s:%s\n", sub_inst_str, sub_id_str);

            printf("\tSubB...");
            e = subscribe(&sub_b_link, subB);
            printf("%s\n", !e ? "done" : "failed");
            if (e) goto cleanup1;
            sub_inst_str = get_address_inst_str(sub_b_link);
            sub_id_str = get_address_id_str(sub_b_link);
            printf("\t\t%s:%s\n", sub_inst_str, sub_id_str);

            printf("\tSubC...");
            e = subscribe(&sub_c_link, subC);
            printf("%s\n", !e ? "done" : "failed");
            if (e) goto cleanup1;
            sub_inst_str = get_address_inst_str(sub_c_link);
            sub_id_str = get_address_id_str(sub_c_link);
            printf("\t\t%s:%s\n", sub_inst_str, sub_id_str);


        cleanup1:
            drop_address(sub_a_link);
            drop_address(sub_b_link);
            drop_address(sub_c_link);
            drop_message(received_announcement);
            //drop_str(sub_a_seed);
            //drop_str(sub_b_seed);
            //drop_str(sub_c_seed);
            drop_str(sub_inst_str);
            drop_str(sub_id_str);

        }
        printf("\n");

        // Update permissions to only include subA, then send message
        {
            address_t const *new_branch_address = NULL;
            address_t const *update_address = NULL;
            address_t const *auth_message_address = NULL;
            permissioned_t const *subA_perm = NULL;
            message_t const *next_message = NULL;
            char const *message_type = "";

            printf("Fetching Subscriber Ids\n");
            e = identifier(&subA_id, subA);
            if (e) goto cleanup;
            char const *sub_a_id_str = get_identifier_str(subA_id);
            printf("%s\n",sub_a_id_str);
            e = identifier(&subB_id, subB);
            if (e) goto cleanup;
            e = identifier(&subC_id, subC);
            if (e) goto cleanup;


            printf("Creating permission list including only subA... ");
            id_lists_t const *id_lists = new_id_lists();
            e = new_permissioned(&subA_perm, subA_id, PERM_READ);
            printf("%s", !e? "permission created... " : "failed");
            if (e) goto cleanup2;
            char const *sub_a_perm_str = get_permissioned_str(subA_perm);
            printf("%s\n",sub_a_perm_str);
            push_user_to_id_lists(id_lists, subA_perm);
            printf("list created\n");


            printf("Making new branch for subA... ");
            e = new_branch(&new_branch_address, auth, base_branch, subA_topic);
            printf("%s\n", !e? "done" : "failed");
            if (e) goto cleanup2;


            printf("Updating Permissions for branch... ");
            e = update_permissions(&update_address, auth, subA_topic, id_lists);
            printf("%s\n", !e? "done" : "failed");
            if (e) goto cleanup2;

            printf("Sending message to new branch... ");
            e = send_message(&auth_message_address, auth, subA_topic, (uint8_t const *)data_payload, sizeof(data_payload), 1, 1);
            printf("%s\n", !e? "done" : "failed");
            if (e) goto cleanup2;

            printf("SubA fetching next messages\n");
            printf("Msg 1... ");
            e = fetch_next_message(&next_message, subA);
            printf("%s. ", !e? "done" : "failed\n");
            if (e) goto cleanup2;
            printf("Type: %s\n", message_type_as_str(next_message -> message_type));
            if (next_message -> message_type == SIGNED_PACKET_MSG) printf("Payload: %s\n", next_message -> payloads.masked_payload.ptr);

            printf("Msg 2... ");
            e = fetch_next_message(&next_message, subA);
            printf("%s. ", !e? "done" : "failed\n");
            if (e) goto cleanup2;
            printf("Type: %s\n", message_type_as_str(next_message -> message_type));
            if (next_message -> message_type == SIGNED_PACKET_MSG) printf("Payload: %s\n", next_message -> payloads.masked_payload.ptr);

            printf("Msg 3... ");
            e = fetch_next_message(&next_message, subA);
            printf("%s. ", !e? "done" : "failed\n");
            if (e) goto cleanup2;
            printf("Type: %s\n", message_type_as_str(next_message -> message_type));
            if (next_message -> message_type == SIGNED_PACKET_MSG) printf("Payload: %s\n", next_message -> payloads.masked_payload.ptr);

            printf("Msg 4... ");
            e = fetch_next_message(&next_message, subA);
            printf("%s", !e? "received message subB should not have received. " : "No next message\n");
            if (!e) printf("Type: %s\n", message_type_as_str(next_message -> message_type));

            printf("\nSubB fetching next messages\n");
            printf("Msg 1... ");
            e = fetch_next_message(&next_message, subB);
            printf("%s", !e? "done. " : "failed\n");
            if (e) goto cleanup2;
            if (!e) printf("Type: %s\n", message_type_as_str(next_message -> message_type));

            printf("Msg 2... ");
            e = fetch_next_message(&next_message, subB);
            printf("%s", !e? "done. " : "failed\n");
            if (e) goto cleanup2;
            if (!e) printf("Type: %s\n", message_type_as_str(next_message -> message_type));

            printf("Msg 3... ");
            e = fetch_next_message(&next_message, subB);
            printf("%s", !e? "received message subB should not have received. " : "no next message\n");
            if (!e) {
                printf("Type: %s\n", message_type_as_str(next_message->message_type));
                // Message shouldn't have been received, so return a bad argument error
                e = ERR_BAD_ARGUMENT;
            } else {
                // Message wasn't received properly, which is intended, so return ok
                e = ERR_OK;
            }

        cleanup2:
            drop_id_lists(id_lists);
            drop_permissioned(subA_perm);
            drop_address(new_branch_address);
            drop_address(update_address);
            drop_message(next_message);
        }
    }

    cleanup:
    printf("Error code: %d\n", e);
    drop_user(subC);
    drop_user(subB);
    drop_user(subA);

    drop_address(ann_link);
    drop_user(auth);
    transport_drop(tsp);

    return (e == ERR_OK ? 0 : 1);
}

