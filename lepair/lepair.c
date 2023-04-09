/*
 * lepair.c
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
#include "ng_l2cap_smp.h"

int timeout = 30;

static int le_connect_result(int s);

static int open_socket(char *node)
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

int iocapmat[5][5] ={
  {0, 0, 1, 0, 1},
  {0, 0, 1, 0, 1},
  {-1, -1, -1, 0, -1},
  {0, 0, 0, 0, 0},
  {-1, -1, -1, 0, -1}
};

int le_smpconnect(bdaddr_t *bd,int hci, int israndom)
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
	l2c.l2cap_bdaddr_type = israndom ? BDADDR_LE_RANDOM : BDADDR_LE_PUBLIC;
	bcopy(bd, &l2c.l2cap_bdaddr, sizeof(*bd));
	if(connect(s, (struct sockaddr *) &l2c, sizeof(l2c)) == 0){
	}else{
	  perror("connect");
	}
	do{
	  handle = le_connect_result(hci);
	}while(handle==0);

	{
	  int fl;
	  fl = fcntl(s, F_GETFL, 0);
	  fcntl(s, F_SETFL, fl&~O_NONBLOCK);
	}
		
	{
	  preq.code = NG_L2CAP_SMP_PAIRREQ;
	  preq.iocap = 4;
	  preq.oobflag = 0;
	  preq.authreq = 1;
	  preq.maxkeysize = 16;
	  preq.ikeydist = 1;
	  preq.rkeydist = 1;
	  write(s,&preq, sizeof(preq));

	  do {
	    int len;
	    len = read(s, &pres, sizeof(pres));
#if 0
	    printf("%d, pi.code %d\n",len, pres.code);
#endif
	    
	  }while(pres.code != NG_L2CAP_SMP_PAIRRES);
#if 0
	  printf("C\n");
	  printf("CODE:%d IOCAP %d %d %d %d %d %d(%d)\n", pres.code,pres.iocap ,
		 pres.oobflag, pres.authreq,
		 pres.maxkeysize, pres.ikeydist, pres.rkeydist, sizeof(pres));
#endif
	}

	{
		socklen_t siz = sizeof(myname);
		char bdastr[40];
		if(getsockname(s, (struct sockaddr *)&myname,&siz)!=0){
			perror("getsockname");
		}
	}
	{
		ng_l2cap_smp_keyinfo mrand,mconfirm,srand,sconfirm;
		ng_l2cap_smp_reqres failed;
		int res;
		uint8_t rval[16];
		int ng = 0;
		unsigned int pin = 0;
		if((preq.iocap<5)&& (pres.iocap<5)){
		  if(iocapmat[pres.iocap][preq.iocap]==1){
		    printf("PIN requested:\n");
		    if(scanf("%u", &pin) != 1){
		      printf("PIN FAIL\n");
		      pin = 0;
		    }
		  }else if(iocapmat[pres.iocap][preq.iocap]== -1){
		    pin = arc4random()%999999;
		  }
		  printf("PIN:%u %x\n", pin, pin);
		}
		bzero(k, sizeof(k));
		k[15] = pin&0xff;
		pin>>=8;
		k[14] = pin&0xff;
		pin>>=8;
		k[13] = pin&0xff;
		arc4random_buf(rval, sizeof(rval));
		swap128(rval, mrand.body);
		mconfirm.code = NG_L2CAP_SMP_PAIRCONF;
		mrand.code = NG_L2CAP_SMP_PAIRRAND;		
		smp_c1(k, rval, (uint8_t *)&preq, (uint8_t *)&pres,
		       (myname.l2cap_bdaddr_type == BDADDR_LE_RANDOM)? 1:0,
		       &myname.l2cap_bdaddr,  (israndom) ? 1 : 0, bd);
		swap128(rval, mconfirm.body);
		write(s, &mconfirm, sizeof(mconfirm));
	       
		res = read(s, &sconfirm, sizeof(sconfirm));
		if(sconfirm.code != NG_L2CAP_SMP_PAIRCONF){
			printf("FAILED:sconfirm.code %d\n", sconfirm.code);
		}
		sleep(5);
		write(s, &mrand, sizeof(mrand));
		res = read(s, &srand, sizeof(srand));
		if(srand.code != NG_L2CAP_SMP_PAIRRAND){
			ng_l2cap_smp_reqres *req;
			req = (void *)&srand;
			printf("FAILED:srand.code %d %d\n", req->code, req->reqres);
			ng = 1;
			goto fail;
		}
		swap128(srand.body, rval);
		smp_c1(k, rval, (uint8_t *)&preq, (uint8_t *)&pres,
		       (myname.l2cap_bdaddr_type == BDADDR_LE_RANDOM)? 1:0,
		       &myname.l2cap_bdaddr,  israndom ? 1:0, bd);
		for(i =0; i< 16; i++){
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
			cp.connection_handle = handle;
			cp.random_number = 0;
			cp.encrypted_diversifier = 0;
			n = sizeof(cp);
			hci_request(hci, NG_HCI_OPCODE(NG_HCI_OGF_LE
				     ,NG_HCI_OCF_LE_START_ENCRYPTION),
				    (char *)&cp, sizeof(cp), (char *)&rp, &n);
			{
				ng_l2cap_smp_keyinfo ki;
				ng_l2cap_smp_masterinfo mi;
				ng_hci_le_start_encryption_cp cp;
				ng_hci_status_rp rp;
				
				uint8_t pkt[30];
				int encok=0, mok=0;
				
				while(encok==0||mok==0){
					read(s, pkt, sizeof(pkt));
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
				}
				printf("device{\n");
				printf("\tname \"thisdevice\";\n ");
				printf("\tbdaddr %s;\n", bt_ntoa(bd, NULL));
				printf("\taddrtype %s;\n", (israndom)?
				       "lernd":"lepub");
				printf("\tediv 0x%04x;\n",mi.ediv);
				cp.encrypted_diversifier = mi.ediv;
				cp.random_number = 0;
				for(i = 0; i < 8 ; i++){
					cp.random_number
						|= (((uint64_t)mi.rand[i])<<(i*8));
				}
				printf("\trand 0x%lx;\n", cp.random_number);

				printf("\tkey 0x");
				for(i = 0 ; i < 16; i++){
					printf("%02x", ki.body[i]);
					cp.long_term_key[i] = ki.body[i];
				}
				printf(";\n");
				printf("\tpin nopin;\n");
				printf("}\n");
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

static int le_connect_result(int s)
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
		perror("HCI_RECV");
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
	//printf("%d\n", lep->subevent_code);
	if(lep->subevent_code != NG_HCI_LEEV_CON_COMPL){
#if 0
		printf("SubEvent%d\n", lep->subevent_code);
		errno = EIO;
#endif
		return 0;
	}
#if 0
	printf("Connection Event:Status%d, handle%d, role%d, address_type:%d\n",
	       cep->status, cep->handle, cep->role, cep->address_type);
	bt_ntoa(&cep->address, addrstring);
	printf("%s %d %d %d %d\n", addrstring, cep->interval, cep->latency,
	       cep->supervision_timeout, cep->master_clock_accuracy);
#endif
	if(cep->status != 0){
		printf("REQUEST ERROR %d\n", cep->status);
		return 0;
	}

	return cep->handle;
}

int main(int argc, char *argv[])
{

	ng_hci_le_set_event_mask_cp lemc;
	char buf[NG_HCI_ADVERTISING_DATA_SIZE];
	char hname[NG_HCI_ADVERTISING_DATA_SIZE-10];
	int s;
	char *node="ubt0hci";
	int len,addr_valid = 0;
	bdaddr_t bd;
	int ch;
	int res = -1,handle = -1;
	int addrrandom = 0;
	
	while((ch = getopt(argc, argv, "r")) != -1){
		switch(ch){
		case 'r':
			addrrandom = 1;
			break;
		default:
			fprintf(stderr, "Usage: %s [-r] bdaddr\n", argv[0]);
			exit(-1);
			break;
		}
	}

	argc -= optind;
	argv += optind;
	
	if(argc > 0){
		addr_valid = bt_aton(argv[0],&bd);
	}
	
	s = open_socket("ubt0hci");

	gethostname(hname, sizeof(hname));
	len = strlen(hname);

	if(addr_valid){
		le_smpconnect(&bd, s, addrrandom);
	}else{
		fprintf(stderr, "Address Invalid\n");
	}
	
	return 0;
}
	
