/*-
 * Copyright (c) 2022-2023 Hans Petter Selasky <hselasky@FreeBSD.org>
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
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/bitstring.h>
#include <sys/select.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <openssl/aes.h>
#include <netgraph/ng_message.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <uuid.h>
#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include "hccontrol.h"
#include "gatt.h"
#include <sqlite3.h>
#include <getopt.h>
#include "sql.h"
#include "service.h"
#include "att.h"
#include "uuidbt.h"
#include "notify.h"

#include <alsa/asoundlib.h>

extern uuid_t uuid_base;

struct midi_parse {
	uint8_t *temp_cmd;
	uint8_t	temp_0[4];
	uint8_t	temp_1[4];
	uint8_t	state;
#define	MIDI_ST_UNKNOWN	 0	/* scan for command */
#define	MIDI_ST_1PARAM	 1
#define	MIDI_ST_2PARAM_1	 2
#define	MIDI_ST_2PARAM_2	 3
#define	MIDI_ST_SYSEX_0	 4
#define	MIDI_ST_SYSEX_1	 5
#define	MIDI_ST_SYSEX_2	 6
};

struct midi_service {
	snd_seq_t *midi_seq;
	struct midi_parse parse;
	int insysex;
};

static void midi_init(struct service *service, int s);
static void midi_notify(void *sc, int charid, unsigned char *buf, size_t len);

static struct service_driver midi_driver __attribute__((used)) __attribute__((section(("driver")))) =
{
	.uuid = {0x03B80E5A,0xEDE8,0x4B33,0xA7,0x51,{0x6C,0xE3,0x4E,0xC4,0xC7,0x00}},
	.init = midi_init,
	.notify = midi_notify
};

static const uint8_t midi_cmd_to_len[16] = {
	[0x0] = 0,			/* reserved */
	[0x1] = 0,			/* reserved */
	[0x2] = 2,			/* bytes */
	[0x3] = 3,			/* bytes */
	[0x4] = 3,			/* bytes */
	[0x5] = 1,			/* bytes */
	[0x6] = 2,			/* bytes */
	[0x7] = 3,			/* bytes */
	[0x8] = 3,			/* bytes */
	[0x9] = 3,			/* bytes */
	[0xA] = 3,			/* bytes */
	[0xB] = 3,			/* bytes */
	[0xC] = 2,			/* bytes */
	[0xD] = 2,			/* bytes */
	[0xE] = 3,			/* bytes */
	[0xF] = 1,			/* bytes */
};

/*
 * The following statemachine, that converts MIDI commands to
 * USB MIDI packets, derives from Linux's usbmidi.c, which
 * was written by "Clemens Ladisch":
 *
 * Returns:
 *    0: No command
 * Else: Command is complete
 */
static uint8_t
midi_convert(struct midi_parse *parse, uint8_t cn, uint8_t b)
{
	uint8_t p0 = (cn << 4);

	if (b >= 0xf8) {
		parse->temp_0[0] = p0 | 0x0f;
		parse->temp_0[1] = b;
		parse->temp_0[2] = 0;
		parse->temp_0[3] = 0;
		parse->temp_cmd = parse->temp_0;
		return (1);

	} else if (b >= 0xf0) {
		switch (b) {
		case 0xf0:		/* system exclusive begin */
			parse->temp_1[1] = b;
			parse->state = MIDI_ST_SYSEX_1;
			break;
		case 0xf1:		/* MIDI time code */
		case 0xf3:		/* song select */
			parse->temp_1[1] = b;
			parse->state = MIDI_ST_1PARAM;
			break;
		case 0xf2:		/* song position pointer */
			parse->temp_1[1] = b;
			parse->state = MIDI_ST_2PARAM_1;
			break;
		case 0xf4:		/* unknown */
		case 0xf5:		/* unknown */
			parse->state = MIDI_ST_UNKNOWN;
			break;
		case 0xf6:		/* tune request */
			parse->temp_1[0] = p0 | 0x05;
			parse->temp_1[1] = 0xf6;
			parse->temp_1[2] = 0;
			parse->temp_1[3] = 0;
			parse->temp_cmd = parse->temp_1;
			parse->state = MIDI_ST_UNKNOWN;
			return (1);
		case 0xf7:		/* system exclusive end */
			switch (parse->state) {
			case MIDI_ST_SYSEX_0:
				parse->temp_1[0] = p0 | 0x05;
				parse->temp_1[1] = 0xf7;
				parse->temp_1[2] = 0;
				parse->temp_1[3] = 0;
				parse->temp_cmd = parse->temp_1;
				parse->state = MIDI_ST_UNKNOWN;
				return (2);
			case MIDI_ST_SYSEX_1:
				parse->temp_1[0] = p0 | 0x06;
				parse->temp_1[2] = 0xf7;
				parse->temp_1[3] = 0;
				parse->temp_cmd = parse->temp_1;
				parse->state = MIDI_ST_UNKNOWN;
				return (2);
			case MIDI_ST_SYSEX_2:
				parse->temp_1[0] = p0 | 0x07;
				parse->temp_1[3] = 0xf7;
				parse->temp_cmd = parse->temp_1;
				parse->state = MIDI_ST_UNKNOWN;
				return (2);
			}
			parse->state = MIDI_ST_UNKNOWN;
			break;
		}
	} else if (b >= 0x80) {
		parse->temp_1[1] = b;
		if ((b >= 0xc0) && (b <= 0xdf)) {
			parse->state = MIDI_ST_1PARAM;
		} else {
			parse->state = MIDI_ST_2PARAM_1;
		}
	} else {			/* b < 0x80 */
		switch (parse->state) {
		case MIDI_ST_1PARAM:
			if (parse->temp_1[1] < 0xf0) {
				p0 |= parse->temp_1[1] >> 4;
			} else {
				p0 |= 0x02;
				parse->state = MIDI_ST_UNKNOWN;
			}
			parse->temp_1[0] = p0;
			parse->temp_1[2] = b;
			parse->temp_1[3] = 0;
			parse->temp_cmd = parse->temp_1;
			return (1);
		case MIDI_ST_2PARAM_1:
			parse->temp_1[2] = b;
			parse->state = MIDI_ST_2PARAM_2;
			break;
		case MIDI_ST_2PARAM_2:
			if (parse->temp_1[1] < 0xf0) {
				p0 |= parse->temp_1[1] >> 4;
				parse->state = MIDI_ST_2PARAM_1;
			} else {
				p0 |= 0x03;
				parse->state = MIDI_ST_UNKNOWN;
			}
			parse->temp_1[0] = p0;
			parse->temp_1[3] = b;
			parse->temp_cmd = parse->temp_1;
			return (1);
		case MIDI_ST_SYSEX_0:
			parse->temp_1[1] = b;
			parse->state = MIDI_ST_SYSEX_1;
			break;
		case MIDI_ST_SYSEX_1:
			parse->temp_1[2] = b;
			parse->state = MIDI_ST_SYSEX_2;
			break;
		case MIDI_ST_SYSEX_2:
			parse->temp_1[0] = p0 | 0x04;
			parse->temp_1[3] = b;
			parse->temp_cmd = parse->temp_1;
			parse->state = MIDI_ST_SYSEX_0;
			return (2);
		default:
			break;
		}
	}
	return (0);
}

static bool
midi_parse_byte_sub(struct snd_seq_event *ev, struct midi_parse *parse, uint8_t data)
{
	switch (midi_convert(parse, 0, data)) {
	case 0:
		return (false);
	case 1:
		break;
	default:
		memset(ev, 0, sizeof(*ev));
		ev->type = SND_SEQ_EVENT_SYSEX;
		ev->flags = SND_SEQ_EVENT_LENGTH_VARIABLE;
		ev->data.ext.len = midi_cmd_to_len[
		    parse->temp_cmd[0] & 0xF];
		ev->data.ext.ptr = parse->temp_cmd + 1;
		return (true);
	}

	memset(ev, 0, sizeof(*ev));
	switch ((parse->temp_cmd[1] & 0xF0) >> 4) {
	case 0x9:
		ev->type = SND_SEQ_EVENT_NOTEON;
		break;
	case 0x8:
		ev->type = SND_SEQ_EVENT_NOTEOFF;
		break;
	case 0xA:
		ev->type = SND_SEQ_EVENT_KEYPRESS;
		break;
	case 0xB:
		ev->type = SND_SEQ_EVENT_CONTROLLER;
		break;
	case 0xC:
		ev->type = SND_SEQ_EVENT_PGMCHANGE;
		break;
	case 0xD:
		ev->type = SND_SEQ_EVENT_CHANPRESS;
		break;
	case 0xE:
		ev->type = SND_SEQ_EVENT_PITCHBEND;
		break;
	case 0xF:
		switch (parse->temp_cmd[1] & 0x0F) {
		case 0x1:
			ev->type = SND_SEQ_EVENT_QFRAME;
			break;
		case 0x2:
			ev->type = SND_SEQ_EVENT_SONGPOS;
			break;
		case 0x3:
			ev->type = SND_SEQ_EVENT_SONGSEL;
			break;
		case 0x6:
			ev->type = SND_SEQ_EVENT_TUNE_REQUEST;
			break;
		case 0x8:
			ev->type = SND_SEQ_EVENT_CLOCK;
			break;
		case 0xA:
			ev->type = SND_SEQ_EVENT_START;
			break;
		case 0xB:
			ev->type = SND_SEQ_EVENT_CONTINUE;
			break;
		case 0xC:
			ev->type = SND_SEQ_EVENT_STOP;
			break;
		case 0xE:
			ev->type = SND_SEQ_EVENT_SENSING;
			break;
		case 0xF:
			ev->type = SND_SEQ_EVENT_RESET;
			break;
		default:
			return (false);
		}
		break;
	default:
		return (false);
	}

	switch (ev->type) {
	case SND_SEQ_EVENT_NOTEON:
	case SND_SEQ_EVENT_NOTEOFF:
	case SND_SEQ_EVENT_KEYPRESS:
		ev->data.note.channel = parse->temp_cmd[1] & 0xF;
		ev->data.note.note = parse->temp_cmd[2] & 0x7F;
		ev->data.note.velocity = parse->temp_cmd[3] & 0x7F;
		break;
	case SND_SEQ_EVENT_PGMCHANGE:
	case SND_SEQ_EVENT_CHANPRESS:
		ev->data.control.channel = parse->temp_cmd[1] & 0xF;
		ev->data.control.value = parse->temp_cmd[2] & 0x7F;
		break;
	case SND_SEQ_EVENT_CONTROLLER:
		ev->data.control.channel = parse->temp_cmd[1] & 0xF;
		ev->data.control.param = parse->temp_cmd[2] & 0x7F;
		ev->data.control.value = parse->temp_cmd[3] & 0x7F;
		break;
	case SND_SEQ_EVENT_PITCHBEND:
		ev->data.control.channel = parse->temp_cmd[1] & 0xF;
		ev->data.control.value =
		    (parse->temp_cmd[2] & 0x7F) |
		    ((parse->temp_cmd[3] & 0x7F) << 7);
		ev->data.control.value -= 8192;
		break;
	case SND_SEQ_EVENT_QFRAME:
	case SND_SEQ_EVENT_SONGSEL:
		ev->data.control.value = parse->temp_cmd[1] & 0x7F;
		break;
	case SND_SEQ_EVENT_SONGPOS:
		ev->data.control.value = (parse->temp_cmd[1] & 0x7F) |
		    ((parse->temp_cmd[2] & 0x7F) << 7);
		break;
	default:
		break;
	}
	return (true);
}

static void
midi_parse_byte(snd_seq_t *seq, struct midi_parse *parse, uint8_t data)
{
	struct snd_seq_event temp;

	if (midi_parse_byte_sub(&temp, parse, data)) {
		snd_seq_ev_set_source(&temp, 0);
		snd_seq_ev_set_subs(&temp);
		snd_seq_ev_set_direct(&temp);
		snd_seq_event_output(seq, &temp);
		snd_seq_drain_output(seq);
	}
}
static int  midi_get_status_datacount(uint8_t sts)
{
	switch(sts&0xf0){
	case 0x80:
	case 0x90:
	case 0xa0:
	case 0xb0:
	case 0xe0:
		return 2;
	case 0xc0:
	case 0xd0:
		return 1;
		break;
	case 0xf0:
		switch(sts){
		case 0xf2:
			return 2;
		case 0xf1:
		case 0xf3:
			return 1;
		}
	default:
		return 0;
	}
	return  0;
}

static void
midi_notify(void *sc, int charid, uint8_t *buf, size_t len)
{
	struct midi_service *ms = sc;
	uint8_t runningStatus = 0 ;
	size_t start = 3;
	size_t stop;
	int header = buf[2];
	int16_t timestamp;
	enum {
		SYSEX,
		TIMESTAMP,
		GETSTS,
		DATA,
	}statm;

	statm = TIMESTAMP;
	if( (header & 0x80 ) == 0){
		printf("Error\n");
		return ;
	}
	if(ms->insysex){
		statm = SYSEX;
	}

	while(start < len){
		switch(statm){
		case SYSEX:
			midi_parse_byte(ms->midi_seq,
					&ms->parse, buf[start]);
			start ++;
			if(buf[start] &0x80)
				statm = TIMESTAMP;
			break;
		case TIMESTAMP:
			if((buf[start]& 0x80) == 0){
				printf("Error\n");
			}
			timestamp = (header &0x3f)<<7;
			timestamp |= (buf[start] & 0x7f);
			start ++;
			if(buf[start] & 0x80){
				statm = GETSTS;
			}else if(runningStatus){
				statm = DATA;
			}else{
				printf("ERROR\n");
				return ;
			}
			break;
		case GETSTS:
			assert((buf[start] & 0x80));
			if ((buf[start] & 0xf0 ) != 0xf0){
				runningStatus = buf[start++];
				statm = DATA;
				break;
			}
			if(buf[start] == 0xf0){
				ms->insysex = 1;
				midi_parse_byte(ms->midi_seq,
						&ms->parse,
						buf[start]);
				start ++;
				statm = SYSEX;
				break;
			} else if(buf[start] == 0xf7){
				ms->insysex = 0;
				midi_parse_byte(ms->midi_seq,
						&ms->parse,
						buf[start]);
				start ++;
				statm = TIMESTAMP;
				break;
			} else {
				int dc = midi_get_status_datacount(buf[start]);
				midi_parse_byte(ms->midi_seq, &ms->parse,
						buf[start++]);
				for(int i = 0; i < dc ;i++){
					midi_parse_byte(ms->midi_seq,
							&ms->parse,
							buf[start++]);
				}
				if (buf[start] &0x80)
				{
					statm = TIMESTAMP;
				} else if (runningStatus){
					statm = DATA;
				} else {
					printf("ERROR\n");
					return;
				}
				break;
			}
		case DATA:
		{
			int dc = midi_get_status_datacount(runningStatus);
			midi_parse_byte(ms->midi_seq,
					&ms->parse,
					runningStatus);
			for(int i = 0 ; i < dc ; i++){
				midi_parse_byte(ms->midi_seq,
						&ms->parse,
						buf[start++]);
			}
			if(buf[start] & 0x80){
				statm = TIMESTAMP;
			}
			break;
		}
		
		}
	}
}

static uuid_t midi_chara = {0x7772E5DB, 0x3868, 0x4112,0xA1,0xA9,{0xF2,0x66,0x9D,0x10,0x6B,0xF3}};

static void
midi_init(struct service *service, int s)
{
	struct midi_service *serv;
	int cid;

	serv = calloc(1, sizeof(*serv));

	if (snd_seq_open(&serv->midi_seq, "default", SND_SEQ_OPEN_DUPLEX, 0)) {
		printf("Cannot open ALSA MIDI control device\n");
		goto error;
	}

	/* set non-blocking mode for event handler */
	snd_seq_nonblock(serv->midi_seq, 1);

	/* XXX could query a better device name */
	snd_seq_set_client_name(serv->midi_seq, "lehid");

	/* read only for now */
	snd_seq_create_simple_port(serv->midi_seq, "BLE MIDI",
	    SND_SEQ_PORT_CAP_READ |
	    SND_SEQ_PORT_CAP_SUBS_READ,
	    SND_SEQ_PORT_TYPE_MIDI_GENERIC |
	    SND_SEQ_PORT_TYPE_APPLICATION);

	service->sc = serv;

	cid = get_cid_by_uuid(service, &midi_chara);
	if (cid != -1) {
		register_notify(cid, service, s);
		return;
	}
	printf("MIDI characteristics not found\n");
error:
	free(serv);
}
