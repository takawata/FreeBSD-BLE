#define L2CAP_SOCKET_CHECKED

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/sysctl.h>
#include <sys/bitstring.h>
#include <sys/select.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <openssl/aes.h>
#include <netgraph/ng_message.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bluetooth.h>

#include "hcsecd.h"

int timeout = 30;

int open_socket(char *node)
{
	struct sockaddr_hci                      addr;  
	int s;
        struct ng_btsocket_hci_raw_filter flt;
	socklen_t slen;
	s = socket(PF_BLUETOOTH, SOCK_RAW, BLUETOOTH_PROTO_HCI);  

	if( s < 0)
		err(2, "Could not create socket");
	memset(&addr, 0, sizeof(addr));
	addr.hci_len = sizeof(addr);
	addr.hci_family = AF_BLUETOOTH;
	
	strncpy(addr.hci_node, node, sizeof(addr.hci_node));

	slen = sizeof(flt);
        if (getsockopt(s, SOL_HCI_RAW, SO_HCI_RAW_FILTER,  &flt, &slen) < 0) {
                perror("Can't set HCI filter");
                exit(1);
        }

	bit_set(flt.event_mask, NG_HCI_EVENT_LE -1);
        if (setsockopt(s, SOL_HCI_RAW, SO_HCI_RAW_FILTER,  &flt, sizeof(flt)) < 0) {
                perror("Can't set HCI filter");
                exit(1);
        }

	return s;
}

void event_loop(int s)
{
	struct sockaddr_hci  haddr;
	socklen_t size;
	int buffer[512],obuffer[512];
	ng_hci_event_pkt_t *event = buffer;
	ng_hci_le_ep *lep = (ng_hci_le_ep * )(event+1);
	ng_hci_le_connection_complete_ep *cep = (ng_hci_le_connection_complete_ep *)(lep+1);
	ng_hci_cmd_pkt_t *cmd = obuffer;
	ng_hci_le_start_encryption_cp *cp =
		(ng_hci_le_start_encryption_cp *)(cmd+1);
	link_key_p key;
	
	for(;;){
		size = sizeof(haddr);
		recvfrom(s, buffer, sizeof(buffer), 0, (struct sockaddr *)& haddr, &size);
		if(event->type != NG_HCI_EVENT_PKT){
			continue;
		}
		if(event->event != NG_HCI_EVENT_LE){
			continue;
		}
		if(lep->subevent_code == NG_HCI_LEEV_CON_COMPL){

		  key = get_key(&cep->address, (cep->address_type==0)?
			  BDADDR_LE_PUBLIC:BDADDR_LE_RANDOM, 1);
		  if(key == NULL)
			  continue;
		  
		  if(key->key == NULL){
			  continue;
		  }
		  memcpy(cp->long_term_key, key->key,
			 sizeof(cp->long_term_key));
		  cp->encrypted_diversifier = key->ediv;
		  cp->random_number = key->rand;
		  cp->connection_handle = cep->handle;		  
		  cmd->type = NG_HCI_CMD_PKT;
		  cmd->opcode = htole16(
			  NG_HCI_OPCODE(NG_HCI_OGF_LE,
					NG_HCI_OCF_LE_START_ENCRYPTION));
		  cmd->length = sizeof(*cp);
		  sendto(s, obuffer, sizeof(*cmd)+cmd->length, 0,
			 (struct sockaddr * )&haddr,
				       sizeof(haddr));
		  
		  printf("SEND CRYPTO\n");

		}
	}
}

int main(int argc, char *argv[])
{
	int s;
	s = open_socket("ubt0hci");
	config_file="./hcsecd.conf";	
	read_config_file();
	event_loop(s);

	return 0;
}
	
