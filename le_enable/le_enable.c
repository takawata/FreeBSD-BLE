/*
 * le_enable.c
 *
 * Copyright (c) 2015 Takanori Watanabe
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id$
 * $FreeBSD$
 */


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
#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include "hccontrol.h"
#include "att.h"
#include "gap.h"
#include "ng_l2cap_smp.h"
#include <getopt.h>

int timeout = 30;

int le_scan_result(int s)
{
	unsigned char buffer[512];
	ng_hci_event_pkt_t	*e = (ng_hci_event_pkt_t *) buffer;
	int i,j,k,l;
	int n;
	int err;
	int numrecord; 
	int sig_str;

	printf("START SCANNING\n");
	n = sizeof(buffer);
	if ((err =hci_recv(s, (char *)buffer, &n)) == ERROR){
	  printf("%d %d %s \n", err, n, strerror(errno));
		return (ERROR);
	}
	printf("HOGEHOGE\n");

	if (n < sizeof(*e)) {
		printf("SIZE%d\n", n);
		errno = EMSGSIZE;
		return (ERROR);
	}

	if (e->type != NG_HCI_EVENT_PKT) {
		printf("Event%d\n", e->type);
		errno = EIO;
		return (ERROR);
	}
	
	printf("SCAN_RESULT %x %x\n", e->event, e->length);
	printf("Subevent  %d\n", buffer[3]);
	numrecord = buffer[4];
	printf("NumRecord %d\n", numrecord);
	j = 5;
	for(i=0; i < numrecord; i++){
	  int length_data;
	  printf("Eventtype %d\n", buffer[j]);
	  j++;
	  printf("AddrType %d\n", buffer[j]);
	  j++;
	  printf("Addr:[%02x:%02x:%02x:%02x:%02x:%02x]\n",
		 buffer[j+5],buffer[j+4],buffer[j+3],
		 buffer[j+2],buffer[j+1],buffer[j]);
	  j+=6;
	  length_data=buffer[j];
	  printf("length_data %d\n", length_data);
	  j++;
	  printf("DATA:");
	  l=0;
	  for(k=0; k<length_data;k++){
		  if(l==0){
			  printf("\n");
			  l = buffer[j];
		  }else{
			  l--;
		  }
		  printf("%02x ", buffer[j]);
		  j++;
	  }
	  sig_str = ((char*)buffer)[j];
	  printf("\n");

	  printf("RSSI: %x (%d db)\n", buffer[j], sig_str);
	}
	return 0;
	
}
int le_set_scan_param(int s, int type, int  interval,  int window, int adrtype,int  policy)
{
	ng_hci_le_set_scan_parameters_cp cp;
	ng_hci_le_set_scan_parameters_rp rp;
	int e,n;
	printf("SCANTYPE%d INTERVAL%d ADDRTYPE%d WINDOW%d POLICY%d\n",
	       type, interval, adrtype,window,policy);
	cp.le_scan_type = type;
	cp.le_scan_interval = interval;
	cp.own_address_type = adrtype;
	cp.le_scan_window = window;
	cp.scanning_filter_policy = policy;
	n = sizeof(rp);
	e = hci_request(s, NG_HCI_OPCODE(NG_HCI_OGF_LE,
					 NG_HCI_OCF_LE_SET_SCAN_PARAMETERS), 
			(void *)&cp, sizeof(cp), (void *)&rp, &n);
			
	printf("SCAN_PARAM %d %d %d\n", e, rp.status, n);
	return 0;
	
}

int le_set_scan_enable(int s, int enable)
{
	ng_hci_le_set_scan_enable_cp cp;
	ng_hci_le_set_scan_enable_rp rp;
	int e,n;

	cp.le_scan_enable = enable;
	cp.filter_duplicates = 0;
	e = hci_request(s, NG_HCI_OPCODE(NG_HCI_OGF_LE,
					 NG_HCI_OCF_LE_SET_SCAN_ENABLE), 
			(void *)&cp, sizeof(cp), (void *)&rp, &n);
			
	printf("SCAN ENABLE%d %d %d\n", e, rp.status, n);
	return 0;
	
}
int le_set_scan_response(int s, int len, char *scan_data)
{
	ng_hci_le_set_scan_response_data_cp cp;
	ng_hci_le_set_scan_response_data_rp rp;
	int n,e;

	if(len > NG_HCI_ADVERTISING_DATA_SIZE){
		printf("ERROR\n");
		return 1;
	}
	cp.scan_response_data_length = len;
	memcpy(cp.scan_response_data, scan_data, len);
	n = sizeof(rp);
	e = hci_request(s, NG_HCI_OPCODE(NG_HCI_OGF_LE,
					 NG_HCI_OCF_LE_SET_SCAN_RESPONSE_DATA), 
			(void *)&cp, sizeof(cp), (void *)&rp, &n);
			
	printf("SEt SCAN RESPONSE %d %d %d\n", e, rp.status, n);
	
	return 0;
}
int le_read_local_supported_features(int s)
{
	ng_hci_le_read_local_supported_features_rp rp;
	int e;
	int n = sizeof(rp);
	e = hci_simple_request(s,
			       NG_HCI_OPCODE(NG_HCI_OGF_LE,
					     NG_HCI_OCF_LE_READ_LOCAL_SUPPORTED_FEATURES), 
			       (void *)&rp, &n);
	printf("LOCAL SUPPOREDED:%d %d %lu\n", e, rp.status, rp.le_features);

	return 0;

}
int le_read_supported_states(int s)
{
	ng_hci_le_read_supported_states_rp rp;
	int e;
	int n = sizeof(rp);
	e = hci_simple_request(s,
			       NG_HCI_OPCODE(NG_HCI_OGF_LE,
					     NG_HCI_OCF_LE_READ_SUPPORTED_STATES),
			       (void *)&rp, &n);
	printf("LE_STATUS:%d %d %lx\n", e, rp.status, rp.le_states);

	return 0;

}

int read_le_buffer_size(int s)
{
	ng_hci_le_read_buffer_size_rp rp;
	int e;
	int n = sizeof(rp);
	e = hci_simple_request(s,
			       NG_HCI_OPCODE(NG_HCI_OGF_LE,
					     NG_HCI_OCF_LE_READ_BUFFER_SIZE), 
			       (void *)&rp, &n);
	printf("READ_LE_BUFFER_SIZE %d %d %d %d\n", e, rp.status, rp.hc_le_data_packet_length, 
	       rp.hc_total_num_le_data_packets);
	if(rp.status == 0 && rp.hc_le_data_packet_length==0){
		ng_hci_read_buffer_size_rp brp;
		n = sizeof(brp);
		e = hci_simple_request(s,
				       NG_HCI_OPCODE(NG_HCI_OGF_INFO,
						     NG_HCI_OCF_READ_BUFFER_SIZE), 
				       (void *)&brp, &n);
		printf("READ BUFFER SIZE %d %d %d %d %d %d \n", e, brp.status,
		       brp.max_acl_size,
		       brp.max_sco_size,
		       brp.num_acl_pkt,
		       brp.num_sco_pkt);
		
	}
	return 0;
}

int set_le_event_mask(int s, uint64_t mask)
{
	ng_hci_le_set_event_mask_cp semc;
	ng_hci_le_set_event_mask_rp rp;  
	int i, n ,e;
	
	
	n = sizeof(rp);
	
	for(i=0; i< NG_HCI_LE_EVENT_MASK_SIZE;i++){
		semc.event_mask[i] = mask&0xff;
		mask>>= 8;
	}
	e = hci_request(s, NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_SET_EVENT_MASK), (void *)&semc, sizeof(semc), (void *)&rp, &n);
	
	printf("LE_EVENT_MASK %d %d\n",e, rp.status);
	return 0;
}


int set_event_mask(int s, uint64_t mask)
{
	ng_hci_set_event_mask_cp semc;
	ng_hci_set_event_mask_rp rp;  
	int i,n,e;
	
	n = sizeof(rp);
	
	for(i=0; i< NG_HCI_EVENT_MASK_SIZE;i++){
		semc.event_mask[i] = mask&0xff;
		mask>>= 8;
	}
	e = hci_request(s, NG_HCI_OPCODE(NG_HCI_OGF_HC_BASEBAND, NG_HCI_OCF_SET_EVENT_MASK), (void *)&semc, sizeof(semc), (void *)&rp, &n);
	
	printf("SET EVENT MASK%d %d\n",e, rp.status);
	return 0;
}
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
	if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		err(2, "Could not bind socket, node=%s", node);
	if (connect(s, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		err(3, "Could not connect socket, node=%s", node);

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
static int mtu = 40;
int num_handle = 0;
static unsigned char sentcmd[12];
int le_att_write(int s, unsigned char *buf, size_t siz)
{
	memcpy(sentcmd, buf, sizeof(sentcmd));
	return write(s, buf, siz);
}
int le_att_read(int s,unsigned char *buf,size_t buflen)
{
  int i;
  int len;
  int ret = 0;
  uint16_t handle,chandle;
  
  for(;;){
	  if((len = read(s, buf, buflen)) <=0 ){
		  return -1;
	  }
	  ret = len;

	  switch(buf[0]){
	  case ATT_OP_ERR:
		  if(buf[1] != sentcmd[0]){
			  printf("ERROR not match\n");
		  }
		  printf("OP %x: Handle %04x CODE %x\n",
			buf[1], buf[2]|(buf[3]<<8), buf[4]);
		  ret = -1;
		  goto end;
	  case ATT_OP_READ_RES:
		  for(i=1; i < len;i++){
			  printf("%02x ", buf[i]);
		  }
		  printf("\n");
		  if(sentcmd[0] != ATT_OP_READ_REQ){
			  printf("SPRIOUS READ\n");
			  ret = -1;
		  }		  
		  goto end;
	  case ATT_OP_FIND_INFO_RES:
		  if(sentcmd[0] != ATT_OP_FIND_INFO_REQ){
			  printf("SPRIOUS FINDRES\n");
			  ret = -1;
		  }
		  goto end;
	  case ATT_OP_MTU_RES:
		  if(sentcmd[0] != ATT_OP_MTU_REQ){
			  printf("SPRIOUS MTU\n");
			  ret = -1;
		  }
		  mtu = buf[1]|(buf[2]<<8);
		  goto end;
	  case ATT_OP_READ_BLOB_RES:
		  for(i=1; i < len;i++){
			  printf("%02x ", buf[i]);
		  }
		  printf("\n");
		  if(sentcmd[0] != ATT_OP_READ_BLOB_REQ){
			  printf("SPRIOUS BLOBRES\n");
			  ret = -1;
		  }
		  printf("READ_BLOB\n");
		  goto end;
	  case ATT_OP_NOTIFY:
		  printf("NOTIFY\n");
		  for(i=1; i < len;i++){
			  printf("%02x ", buf[i]);
		  }
		  printf("\n");
		  break;
	  case ATT_OP_INDICATE:
		  printf("INDICATE\n");
		  break;

	  case ATT_OP_FIND_INFO_REQ:
		  printf("FIND_INFO\n");
		  break;
	  case ATT_OP_FIND_TYPE_REQ:
		  printf("FIND_TYPE\n");
		  for(i=1; i < len;i++){
			  printf("%02x ", buf[i]);
		  }
		  printf("\n");
		  break;
	  default:
		  printf("UNKNOWN\n");
		  for(i=0; i < len;i++){
			  printf("%02x ", buf[i]);
		  }
		  printf("\n");
		  ret = -1;
		  goto end;
	  }
  }
end:
  return ret;
}

int le_l2connect(bdaddr_t *bd,int hci, int securecon)
{
	struct sockaddr_l2cap l2c;
	int s;
	unsigned char buf[40];
	ssize_t len;
	int i;
	uint16_t buid,handle = 1;
	uint16_t conhandle = 0;
	int count;
	uint16_t enc;

	s = socket(PF_BLUETOOTH, SOCK_SEQPACKET,
		   BLUETOOTH_PROTO_L2CAP);  
	l2c.l2cap_len = sizeof(l2c);
	l2c.l2cap_family = AF_BLUETOOTH;
	l2c.l2cap_psm = 0;
	l2c.l2cap_cid = NG_L2CAP_ATT_CID;
	l2c.l2cap_bdaddr_type = BDADDR_LE_PUBLIC;
	bcopy(bd, &l2c.l2cap_bdaddr, sizeof(*bd));
	printf("CONNECT\n");
	enc = 1;

	if(securecon){
		if(setsockopt(s, SOL_L2CAP, SO_L2CAP_ENCRYPTED, &enc, sizeof(enc))<0){
			err(2, "SETSOCKOPT FAILED");
		}
	}

	if(connect(s, (struct sockaddr *) &l2c, sizeof(l2c))!= 0){
		perror("connect");
	}
	printf("CONNECTOK\n");	

	buf[0]=ATT_OP_MTU_REQ;
	buf[1]=mtu&0xff;
	buf[2]=mtu>>8;
	le_att_write(s,buf,3);
	le_att_read(s,buf,sizeof(buf));
	printf("MTU %d\n", mtu);
	for(;;){
		printf("FIND_INFO\n");
		buf[0] = ATT_OP_FIND_INFO_REQ;
		buf[1] = handle &0xff;
		buf[2] = handle >>8;
		buf[3] = 0xff;
		buf[4] = 0xff;
		le_att_write(s,buf,5);
		if((len = le_att_read(s, buf,sizeof(buf)))<0){
			break;
		}
		if(buf[1] == 1){
			printf("UIDS:");
			for(i=2; i < len;i+= 4){
				handle = buf[i+1]<<8|buf[i];
				buid = buf[i+3]<<8|buf[i+2];
				printf("%04x:%04x ", handle, buid);
				num_handle++;	  
				hent = realloc(hent,
					       sizeof(struct handle_entry)
					       *num_handle);
				hent[num_handle-1].handle = handle;
				hent[num_handle-1].uuid16 = buid;
				hent[num_handle-1].permission = 0;
			}
		}else if(buf[1] == 2){
			printf("%04x:UUID128\n", handle);
			for(i=2; i < len; i++){
				printf("%02x ", buf[i]);
			}
			
		}
		printf("\n");
		handle++;
	}
	gap_probe(s,hent, num_handle);

	return 0;
}
static int smp_e(const unsigned char *k,const unsigned char *data, unsigned char *out)
{
	AES_KEY key;
	AES_set_encrypt_key(k, 128, &key);
	AES_ecb_encrypt(data, out, &key, AES_ENCRYPT);
	return 0;
}
static int smp_s1(const uint8_t *k, uint8_t *r1, uint8_t *r2, uint8_t *out)
{
	uint8_t r[16];
	int i;
	bcopy(r1+8, r, 8);
	bcopy(r2+8, r+8, 8);
	return smp_e(k, r, out);
}
static int smp_c1(uint8_t *k, uint8_t *r, uint8_t *preq,
		  uint8_t *pres, uint8_t iat, bdaddr_t *ia,
		  uint8_t rat, bdaddr_t *ra)
{
	uint8_t p1[16];
	uint8_t p2[16];
	uint8_t tmp[16];
	int i;
	for(i = 0; i< 7; i++){
		p1[i+7] = preq[6-i];
		p1[i] = pres[6-i];
	}
	p1[14] = rat;
	p1[15] = iat;
	bzero(p2, sizeof(p2));
	for(i = 0; i< 6; i++){
		p2[i+4] = ia->b[5-i];
		p2[i+10] = ra->b[5-i];
	}
	printf("P1 ");
	for(i=0; i<16; i++){
	  printf("%02x ",p1[i]);
	}
	printf("\nP2 ");
	for(i=0; i<16; i++){
	  printf("%02x ",p2[i]);
	}
	printf("\n");
	for(i = 0; i < 16; i++){
		r[i] = r[i]^p1[i];
	}
	
	smp_e(k, r, tmp);
	for(i = 0; i < 16; i++){
		tmp[i] = tmp[i]^p2[i];
	}
	smp_e(k, tmp, r);
	
	return 0;
}
int smp_c1_unittest()
{
  int i;
  uint8_t tpq[7] = {0x01, 0x01, 0x00, 0x00, 0x10, 0x07, 0x07};
  
  uint8_t tps[7] = {0x02, 0x03, 0x00, 0x00, 0x08, 0x00, 0x05};
  bdaddr_t bdi = {.b = {0xa6, 0xa5, 0xa4, 0xa3, 0xa2, 0xa1}};
  bdaddr_t bdr = {.b = {0xb6, 0xb5, 0xb4, 0xb3, 0xb2, 0xb1}};
  uint8_t rav[16] = {0x57, 0x83, 0xd5, 0x21, 0x56, 0xad, 0x6f,0x0e, 0x63, 0x88, 0x27, 0x4e, 0xc6, 0x70, 0x2e, 0xe0};
  uint8_t k[16];
  bzero(k, sizeof(k));
  smp_c1(k, rav, tpq, tps, 1, &bdi, 0, &bdr);
  for(i = 0 ;i < sizeof(rav); i++){
    printf("%02x ", rav[i]);		  
  }
  printf("\n");
  return 0;
}
void inline swap128(uint8_t *src, uint8_t *dst)
{
	int i;
	for(i=0;i < 16; i++){
		dst[i] = src[15-i];
	}
}
	
int le_smpconnect(bdaddr_t *bd,int hci)
{
	struct sockaddr_l2cap l2c;
	int s;
	unsigned char buf[40];
	ssize_t len;
	int i;
	int count;
	int handle = 0;
	ng_l2cap_smp_pairinfo preq, pres;
	fd_set rfds,wfds;
	uint8_t k[16];
	int conok = 0;
	struct sockaddr_l2cap myname;

	s = socket(PF_BLUETOOTH, SOCK_SEQPACKET|SOCK_NONBLOCK,
		   BLUETOOTH_PROTO_L2CAP);

	l2c.l2cap_len = sizeof(l2c);
	l2c.l2cap_family = AF_BLUETOOTH;
	l2c.l2cap_psm = 0;
	l2c.l2cap_cid = NG_L2CAP_SMP_CID;
	l2c.l2cap_bdaddr_type = BDADDR_LE_PUBLIC;
	bcopy(bd, &l2c.l2cap_bdaddr, sizeof(*bd));
	printf("CONNECT\n");
	if(connect(s, (struct sockaddr *) &l2c, sizeof(l2c)) == 0){
	  
		printf("CONNECTOK\n");		
	}else{
	  perror("connect");
	}
#if 1
	do{
	  handle = le_connect_result(hci);
	}while(handle==0);
#endif

	printf("handle%x\n", handle);
	{
	  int fl;
	  fl = fcntl(s, F_GETFL, 0);
	  fcntl(s, F_SETFL, fl&~O_NONBLOCK);
	}
		
	printf("HOGEHOGE\n");
	{
	  preq.code = NG_L2CAP_SMP_PAIRREQ;
	  preq.iocap = 4;
	  preq.oobflag = 0;
	  preq.authreq = 1;
	  preq.maxkeysize = 16;
	  preq.ikeydist = 1;
	  preq.rkeydist = 1;
	  write(s,&preq, sizeof(preq));
	  printf("A\n");
	  do {
	    int len;
	    printf("B\n");
	    len = read(s, &pres, sizeof(pres));
	    printf("%d, pi.code %d\n",len, pres.code);
	    
	  }while(pres.code != NG_L2CAP_SMP_PAIRRES);
	  printf("C\n");
	  printf("%d %d %d %d %d %d %d(%d)\n", pres.code,pres.iocap ,
		 pres.oobflag, pres.authreq,
		 pres.maxkeysize, pres.ikeydist, pres.rkeydist, sizeof(pres));
	}
	{
		socklen_t siz = sizeof(myname);
		char bdastr[40];
		if(getsockname(s, (struct sockaddr *)&myname,&siz)!=0){
			perror("getsockname");
		}
		printf("%d\n", myname.l2cap_bdaddr_type);
		printf("%s\n", bt_ntoa(&myname.l2cap_bdaddr, NULL));
	}
	{
		ng_l2cap_smp_keyinfo mrand,mconfirm,srand,sconfirm;
		ng_l2cap_smp_reqres failed;
		int res;
		uint8_t rval[16];
		int ng = 0;
		bzero(k, sizeof(k));
		arc4random_buf(rval, sizeof(rval));
		swap128(rval, mrand.body);
		mconfirm.code = NG_L2CAP_SMP_PAIRCONF;
		mrand.code = NG_L2CAP_SMP_PAIRRAND;		
		smp_c1(k, rval, (uint8_t *)&preq, (uint8_t *)&pres,
		       (myname.l2cap_bdaddr_type == BDADDR_LE_RANDOM)? 1:0,
		       &myname.l2cap_bdaddr,  0, bd);
		swap128(rval, mconfirm.body);
		write(s, &mconfirm, sizeof(mconfirm));
	       
		res = read(s, &sconfirm, sizeof(sconfirm));
		printf("%d\n", res);
		if(sconfirm.code != NG_L2CAP_SMP_PAIRCONF){
			printf("sconfirm.code %d\n", sconfirm.code);
		}
		write(s, &mrand, sizeof(mrand));
		res = read(s, &srand, sizeof(srand));
		printf("%d\n", res);		
		if(srand.code != NG_L2CAP_SMP_PAIRRAND){
			printf("srand.code %d\n", srand.code);
			ng = 1;
			goto fail;
		}
		swap128(srand.body, rval);
		smp_c1(k, rval, (uint8_t *)&preq, (uint8_t *)&pres,
		       (myname.l2cap_bdaddr_type == BDADDR_LE_RANDOM)? 1:0,
		       &myname.l2cap_bdaddr,  0, bd);
		for(i =0; i< 16; i++){
			printf("%x:%x,", rval[i], sconfirm.body[15-i]);
			if(rval[i] != sconfirm.body[15-i]){
				ng = 1;
				goto fail;
			}
		}
		

		{
			uint8_t mr[16], sr[16],stk[16];
			ng_hci_le_start_encryption_cp cp;
			ng_hci_status_rp rp;
			uint8_t buf[128];
			ng_hci_event_pkt_t *ep;
			ng_hci_encryption_change_ep *eep;
			int n;
			swap128(mrand.body, mr);
			swap128(srand.body, sr);
			smp_s1(k, sr, mr, stk);
			swap128(stk, cp.long_term_key);
#if 1
			cp.connection_handle = handle;
			cp.random_number = 0;
			cp.encrypted_diversifier = 0;
			n = sizeof(cp);
			hci_request(hci, NG_HCI_OPCODE(NG_HCI_OGF_LE
				     ,NG_HCI_OCF_LE_START_ENCRYPTION),
				    (char *)&cp, sizeof(cp), (char *)&rp, &n);
#endif
			printf("LE_ENC OK\n");
			{
				ng_l2cap_smp_keyinfo ki;
				ng_l2cap_smp_masterinfo mi;
				ng_hci_le_start_encryption_cp cp;
				ng_hci_status_rp rp;
				
				uint8_t pkt[30];
				int encok=0, mok=0;
				
				while(encok==0||mok==0){
					read(s, pkt, sizeof(pkt));
					printf("%d\n", pkt[0]);
					switch(pkt[0]){
					case NG_L2CAP_SMP_MASTERINFO:
						mok=1;
						bcopy(pkt, &mi,sizeof(mi));
						break;
					case NG_L2CAP_SMP_ENCINFO:
						encok=1;
						bcopy(pkt,&ki, sizeof(ki));
						break;
						
					}
					printf("%d %d\n", encok, mok);
				}
				printf("EDIV:%x \nRAND",mi.ediv);
				cp.encrypted_diversifier = mi.ediv;
				cp.random_number = 0;
				for(i = 0; i < 8 ; i++){
					printf("%02x ", mi.rand[i]);
					cp.random_number
						|= (((uint64_t)mi.rand[i])<<(i*8));
				}

				printf("\nKEY");
				for(i = 0 ; i < 16; i++){
					printf("%02x ", ki.body[i]);
					cp.long_term_key[i] = ki.body[i];
				}
				printf("\n");
				arc4random_buf(ki.body, sizeof(ki.body));
				ki.code = NG_L2CAP_SMP_ENCINFO;
				write(s, &ki, sizeof(ki));
				mi.ediv = arc4random()&0xffff;
				arc4random_buf(&mi.rand, sizeof(mi.rand));
				mi.code = NG_L2CAP_SMP_MASTERINFO;
				write(s, &mi, sizeof(mi));
				sleep(4);
				cp.connection_handle = handle;


				n = sizeof(cp);
				hci_request(hci, NG_HCI_OPCODE(NG_HCI_OGF_LE
							       ,NG_HCI_OCF_LE_START_ENCRYPTION),
					    (char *)&cp, sizeof(cp), (char *)&rp, &n);
				sleep(30);
				
			}
			
				
		}

	fail:
		if(ng){
			failed.code = NG_L2CAP_SMP_PAIRFAIL;
			failed.reqres = 4;
			write(s, &failed, sizeof(failed));
		}
	}
	return 0;
}

int le_connect(int s, bdaddr_t *bd)
{
	ng_hci_le_create_connection_cp cp;
	ng_hci_status_rp rp;  
	int n,n2;
	
	n = sizeof(cp);
	n2 = sizeof(rp);

	memcpy(&cp.peer_addr, bd, sizeof(*bd));
	printf("%x %x %x %x %x %x \n", cp.peer_addr.b[0],
	       cp.peer_addr.b[1],
	       cp.peer_addr.b[2],
	       cp.peer_addr.b[3],
	       cp.peer_addr.b[4],	       
	       cp.peer_addr.b[5]);

	printf("%x %x %x %x %x %x \n", bd->b[0],
	       bd->b[1],
	       bd->b[2],
	       bd->b[3],
	       bd->b[4],	       
	       bd->b[5]);
	cp.peer_addr_type = 0; 
	cp.own_address_type = 0; 
	cp.scan_interval = htobs(0x4);
	cp.scan_window = htobs(0x04);
	cp.filter_policy = 0;
	cp.conn_interval_min = htobs(0x0f); 
	cp.conn_interval_max = htobs(0x0f); //4sec.
	cp.conn_latency = htobs(0);
	cp.supervision_timeout = htobs(0xc80);
	cp.min_ce_length = htobs(1);
	cp.max_ce_length = htobs(1);
	
	hci_request(s, NG_HCI_OPCODE(NG_HCI_OGF_LE,
				    NG_HCI_OCF_LE_CREATE_CONNECTION),
		    (const char *)&cp, n, (char *)&rp, &n2);
	printf("STATUS:%d\n", rp.status);

	return rp.status;


	
}

int le_connect_result(s)
{
	char buffer[512];
	ng_hci_event_pkt_t *e;
	ng_hci_le_ep *lep;
	ng_hci_le_connection_complete_ep *cep;
	int n;
	char addrstring[50];
	int err;

	e = (ng_hci_event_pkt_t *)buffer;
	lep = (ng_hci_le_ep *)(((char *)e)+(sizeof(*e)));
	cep = (ng_hci_le_connection_complete_ep *)(((char *)lep)+(sizeof(*lep)));
	n = sizeof(buffer);
	if((err = hci_recv(s, buffer, &n))==ERROR){
		printf("RECV Error\n");
		return 0;
	}
	if(n < sizeof(*e)){
		errno = EMSGSIZE;
		return 0;
	}
	if(e->type != NG_HCI_EVENT_PKT){
		printf("Event%d\n", e->type);
		errno = EIO;
		return 0;
	}
	printf("%d\n", lep->subevent_code);
	if(lep->subevent_code != NG_HCI_LEEV_CON_COMPL){
		printf("SubEvent%d\n", lep->subevent_code);
		errno = EIO;
		return 0;
	}
	printf("Connection Event:Status%d, handle%d, role%d, address_type:%d\n",
	       cep->status, cep->handle, cep->role, cep->address_type);
	bt_ntoa(&cep->address, addrstring);
	printf("%s %d %d %d %d\n", addrstring, cep->interval, cep->latency,
	       cep->supervision_timeout, cep->master_clock_accuracy);
	if(cep->status != 0){
		printf("REQUEST ERROR %d\n", cep->status);
		return 0;
	}

	return cep->handle;
}
int request_disconnect(int s, int handle, int reason)
{
	ng_hci_discon_cp cp;
	ng_hci_status_rp ep;
	int n;
	cp.con_handle = handle;
	cp.reason = reason;
	n = sizeof(ep);
	hci_request(s, NG_HCI_OPCODE(NG_HCI_OGF_LINK_CONTROL,NG_HCI_OCF_DISCON),
		    (char *)&cp, sizeof(cp), (char *)&ep, &n);
	printf("DISCONNECT:%d\n", ep.status);
	return ep.status;
}

int main(int argc, char *argv[])
{

	ng_hci_le_set_event_mask_cp lemc;
	char buf[NG_HCI_ADVERTISING_DATA_SIZE];
	char hname[NG_HCI_ADVERTISING_DATA_SIZE-10];
	int s;
	int ch;
	char *node="ubt0hci";
	int len,addr_valid = 0;
	bdaddr_t bd;
	int sflag = 0;
	int res = -1,handle = -1;
	while((ch = getopt(argc, argv, "s") )!= -1){
		switch(ch){
		case 's':
			sflag = 1;
			break;
		default:
			fprintf(stderr, "Usage: %s [-s] bdaddr\n", argv[0]);
			exit(-1);
			break;
		}
	}
	argc -= optind;
	argv += optind;
	if(argc>0){
	  addr_valid = bt_aton(argv[0],&bd);
	}
	s = open_socket("ubt0hci");
	
	set_event_mask(s,0x20001fffffffffff);
	set_le_event_mask(s, 0x1f);
	read_le_buffer_size(s);
	le_read_local_supported_features(s);
	le_set_scan_param(s, 0, 0x12, 0x12, 0, 0);
	buf[0] = 2;
	buf[1] = 1;
	buf[2] = 0;
	buf[3] = 8;
	
	gethostname(hname, sizeof(hname));
	len = strlen(hname);
#if 1
	memcpy(&buf[5], hname, len);
	buf[4] = len - 1;
	le_set_scan_response(s, sizeof(buf), buf);
	le_read_supported_states(s);
	le_set_scan_enable(s,1);
	le_scan_result(s);
	le_set_scan_enable(s,0);
#endif
	if(addr_valid){
#if 0
	  res = 1;
	  res = le_connect(s, &bd);
	  if(res == 0){
		  handle = le_connect_result(s);
	  }else{
		  printf("CONNECT FAILED\n");
		  return -1;
	  }
	  printf("Handle %x\n", handle);
#endif
	  le_l2connect(&bd, s, sflag);
	  //le_smpconnect(&bd, s);
	  
	}
	
	return 0;
}
	
