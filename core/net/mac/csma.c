/*
 * Copyright (c) 2010, Swedish Institute of Computer Science.
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
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *         A Carrier Sense Multiple Access (CSMA) MAC layer
 * \author
 *         Adam Dunkels <adam@sics.se>
 */

#include "net/mac/csma.h"
#include "net/mac/framer-be.h"
#include "net/packetbuf.h"
#include "net/queuebuf.h"

#include "sys/ctimer.h"
#include "sys/clock.h"

#include "lib/random.h"

#include "net/netstack.h"

#include "lib/list.h"
#include "lib/memb.h"


#define DEBUG 1
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else /* DEBUG */
#define PRINTF(...)
#endif /* DEBUG */

/*Useful macros*/

#ifdef TRUE
	#undef TRUE
#else
	#define TRUE	(1)
#endif

#ifdef FALSE
	#undef FALSE
#else
	#define FALSE	(0)
#endif

#ifdef _ALWAYS_
	#undef _ALWAYS_
#else
	#define _ALWAYS_ (1)
#endif


/* The maximum number of co-existing neighbor queues */
#ifdef CSMA_CONF_MAX_NEIGHBOR_QUEUES
#define CSMA_MAX_NEIGHBOR_QUEUES CSMA_CONF_MAX_NEIGHBOR_QUEUES
#else
#define CSMA_MAX_NEIGHBOR_QUEUES 2
#endif /* CSMA_CONF_MAX_NEIGHBOR_QUEUES */

/* The maximum number of pending packet per neighbor */
#ifdef CSMA_CONF_MAX_PACKET_PER_NEIGHBOR
#define CSMA_MAX_PACKET_PER_NEIGHBOR CSMA_CONF_MAX_PACKET_PER_NEIGHBOR
#else
#define CSMA_MAX_PACKET_PER_NEIGHBOR MAX_QUEUED_PACKETS
#endif /* CSMA_CONF_MAX_PACKET_PER_NEIGHBOR */


/* Constants of the IEEE 802.15.4 standard */

/* macMinBE: Initial backoff exponent. Range 0--CSMA_MAX_BE */
#ifdef CSMA_CONF_MIN_BE
#define CSMA_MIN_BE CSMA_CONF_MIN_BE
#else
#define CSMA_MIN_BE 0
#endif

/* macMaxBE: Maximum backoff exponent. Range 3--8 */
#ifdef CSMA_CONF_MAX_BE
#define CSMA_MAX_BE CSMA_CONF_MAX_BE
#else
#define CSMA_MAX_BE 4
#endif

/* macMaxCSMABackoffs: Maximum number of backoffs in case of channel busy/collision. Range 0--5 */
#ifdef CSMA_CONF_MAX_BACKOFF
#define CSMA_MAX_BACKOFF CSMA_CONF_MAX_BACKOFF
#else
#define CSMA_MAX_BACKOFF 5
#endif

/* macMaxFrameRetries: Maximum number of re-transmissions attampts. Range 0--7 */
#ifdef CSMA_CONF_MAX_FRAME_RETRIES
#define CSMA_MAX_MAX_FRAME_RETRIES CSMA_CONF_MAX_FRAME_RETRIES
#else
#define CSMA_MAX_MAX_FRAME_RETRIES 7
#endif


/* CSMA timing default values (do we need to create tsch-conf.h */

/*Should be configurable, just use default value for now*/
#define CSMA_CONF_RX_WAIT 2200

#define CSMA_DEFAULT_TS_CCA_OFFSET         1800
#define CSMA_DEFAULT_TS_CCA                128
#define CSMA_DEFAULT_TS_TX_OFFSET          4000
#define CSMA_DEFAULT_TS_RX_OFFSET          (CSMA_DEFAULT_TS_TX_OFFSET - (CSMA_CONF_RX_WAIT / 2))
#define CSMA_DEFAULT_TS_RX_ACK_DELAY       3600
#define CSMA_DEFAULT_TS_TX_ACK_DELAY       4000
#define CSMA_DEFAULT_TS_RX_WAIT            CSMA_CONF_RX_WAIT
#define CSMA_DEFAULT_TS_ACK_WAIT           800
#define CSMA_DEFAULT_TS_RX_TX              2072
#define CSMA_DEFAULT_TS_MAX_ACK            2400
#define CSMA_DEFAULT_TS_MAX_TX             4256
#define CSMA_DEFAULT_TS_ACTIVE_LENGTH      122400
#define CSMA_DEFAULT_TS_INACTIVE_LENGTH    122400
#define CSMA_DEFAULT_TS_SEND_BEACON_GUARD  1000
#define CSMA_DEFAULT_TS_BI			       3916800	/*BO=8, SO=7*/
#define CSMA_DEFAULT_TS_SD                 1958400

#define DEFAULT_BO		(8)
#define DEFAULT_SO		(7)

/* Superframe structure constants */
#define LAST_ACTIVE_TS 		(15)
#define LAST_INACTIVE_TS	(31)
#define FIRST_INACTIVE_TS	(16)


/* TSN value used when we are not in slotted CSMA operation */
#define MAX_TSN_VALUE	(32)
#define TSN_INVALID		(0xFF) /* This node has not been associated */
#define TSN_INACTIVE	(0xFE) /* This node is associated but in the inactive period*/


/************ Types ***********/

/* CSMA timeslot timing elements. Used to index timeslot timing
 * of different units, such as rtimer tick or micro-second */
enum csma_timeslot_timing_elements {
  csma_ts_cca_offset,
  csma_ts_cca,
  csma_ts_tx_offset,
  csma_ts_rx_offset,
  csma_ts_rx_ack_delay,
  csma_ts_tx_ack_delay,
  csma_ts_rx_wait,
  csma_ts_ack_wait,
  csma_ts_rx_tx,
  csma_ts_max_ack,
  csma_ts_max_tx,
  csma_ts_active_length,
  csma_ts_inactive_length,
  csma_ts_send_beacon_guard,
  csma_ts_bi,				/*Beacon interval*/
  csma_ts_sd,				/*Superframe duration*/
  csma_ts_elements_count, /* Not a timing element */
};


/* Default slotted CSMA timing (in micro-second) */
static const uint32_t csma_default_timing_us[csma_ts_elements_count] = {
  CSMA_DEFAULT_TS_CCA_OFFSET,
  CSMA_DEFAULT_TS_CCA,
  CSMA_DEFAULT_TS_TX_OFFSET,
  CSMA_DEFAULT_TS_RX_OFFSET,
  CSMA_DEFAULT_TS_RX_ACK_DELAY,
  CSMA_DEFAULT_TS_TX_ACK_DELAY,
  CSMA_DEFAULT_TS_RX_WAIT,
  CSMA_DEFAULT_TS_ACK_WAIT,
  CSMA_DEFAULT_TS_RX_TX,
  CSMA_DEFAULT_TS_MAX_ACK,
  CSMA_DEFAULT_TS_MAX_TX,
  CSMA_DEFAULT_TS_ACTIVE_LENGTH,
  CSMA_DEFAULT_TS_INACTIVE_LENGTH,
  CSMA_DEFAULT_TS_SEND_BEACON_GUARD,
  CSMA_DEFAULT_TS_BI,
  CSMA_DEFAULT_TS_SD,
};
/* CSMA timeslot timing (in rtimer ticks) */
rtimer_clock_t csma_timing[csma_ts_elements_count];

/* By default: check that rtimer runs at >=32kHz and use a guard time of 10us */
#if RTIMER_SECOND < (32 * 1024)
#error "PAN-BE: RTIMER_SECOND < (32 * 1024)"
#endif
#if CONTIKI_TARGET_COOJA || CONTIKI_TARGET_COOJA_IP64
/* Use 0 usec guard time for Cooja Mote with a 1 MHz Rtimer*/
#define RTIMER_GUARD 0u
#elif RTIMER_SECOND >= 200000
#define RTIMER_GUARD (RTIMER_SECOND / 100000)
#else
#define RTIMER_GUARD 2u
#endif

/* Wait for a condition with timeout t0+offset. */
#if CONTIKI_TARGET_COOJA || CONTIKI_TARGET_COOJA_IP64
#define BUSYWAIT_UNTIL_ABS(cond, t0, offset) \
  while(!(cond) && RTIMER_CLOCK_LT(RTIMER_NOW(), (t0) + (offset))) { \
    simProcessRunValue = 1; \
    cooja_mt_yield(); \
  };
#else
#define BUSYWAIT_UNTIL_ABS(cond, t0, offset) \
  while(!(cond) && RTIMER_CLOCK_LT(RTIMER_NOW(), (t0) + (offset))) ;
#endif /* CONTIKI_TARGET_COOJA || CONTIKI_TARGET_COOJA_IP64 */

/*---------------------------------------------------------------------------*/
/* Schedule slot operation conditionally, and YIELD if success only.
 * Always attempt to schedule RTIMER_GUARD before the target to make sure to wake up
 * ahead of time and then busy wait to exactly hit the target. */
#define TSN_SCHEDULE_AND_YIELD(pt, tm, ref_time, offset) \
  do { \
    if(tsn_update_schedule(tm, ref_time, offset - RTIMER_GUARD)) { \
      PT_YIELD(pt); \
    } \
    BUSYWAIT_UNTIL_ABS(0, ref_time, offset); \
  } while(0);

/* Link options */
#define LINK_OPTION_TX              1
#define LINK_OPTION_RX              2
#define LINK_OPTION_SHARED          4
#define LINK_OPTION_TIME_KEEPING    8

/* 802.15.4e link types.
 * LINK_TYPE_ADVERTISING_ONLY is an extra one: for EB-only links. */
enum link_type { LINK_TYPE_NORMAL, LINK_TYPE_ADVERTISING, LINK_TYPE_ADVERTISING_ONLY };

struct scsma_link {
  /* Links are stored as a list: "next" must be the first field */
  struct scsma_link *next;
  /* MAC address of neighbor */
  linkaddr_t addr;
  /* Timeslot for this link */
  uint16_t timeslot;
  /* A bit string that defines
   * b0 = Transmit, b1 = Receive, b2 = Shared, b3 = Timekeeping, b4 = reserved */
  uint8_t link_options;
  /* Type of link. NORMAL = 0. ADVERTISING = 1, and indicates
     the link may be used to send an beacon frames. */
  enum link_type link_type;
  /* Any other data for upper layers */
  void *data;
};

/***** Beacon frame link *****/
/*
 * Use virtual address for beacon frames
 * timeslot allocated for this frame is always 0
 * link option: Transmit
 * link_type: ADVERTISING
 */
#if 0
const struct scdma_link beacon_frame_link = {NULL, { { 0, 0 } }, 1, 1, LINK_TYPE_ADVERTISING};
#endif

/* Packet metadata */
struct qbuf_metadata {
	mac_callback_t sent;
	void *cptr;
	uint8_t max_transmissions;
};

/* Every neighbor has its own packet queue */
struct neighbor_queue {
	struct neighbor_queue *next;
	linkaddr_t addr;
	struct ctimer transmit_timer;
	uint8_t transmissions;
	uint8_t collisions;
	uint16_t transmit_tsn;		/*Used for slotted CSMA*/
	LIST_STRUCT(queued_packet_list);
};

static struct neighbor_queue *nq = NULL;

/* The actual queuebuf data , copied from queuebuf.c*/
struct queuebuf_data {
  uint8_t data[PACKETBUF_SIZE];
  uint16_t len;
  struct packetbuf_attr attrs[PACKETBUF_NUM_ATTRS];
  struct packetbuf_addr addrs[PACKETBUF_NUM_ADDRS];
};

/* Beacon frame */
struct queuebuf_data beacon_frame;
/*TSN information struct*/

typedef struct tsn_info{
	uint8_t volatile tsn_value;
	uint8_t	is_tsn_start_time_set;
	rtimer_clock_t volatile tsn_start_time;
}tsn_into_t;

/* Updated by keep_tsn_info process, used in different process */
static tsn_into_t current_tsn = {TSN_INVALID, FALSE, (rtimer_clock_t)0 };


#if LINKADDR_SIZE == 8
/* 802.15.4 broadcast MAC address  */
const linkaddr_t broadcast_address = { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } };
/* Address used for the EB virtual neighbor queue */
const linkaddr_t beacon_address = { { 0, 0, 0, 0, 0, 0, 0, 0 } };
#else /* LINKADDR_SIZE == 8 */
const linkaddr_t broadcast_address = { { 0xff, 0xff } };
const linkaddr_t beacon_address = { { 0, 0 } }; /*Virtual address for beacon frames*/
#endif /* LINKADDR_SIZE == 8 */


/* Temporal hand-coded value for Superfame time period on Beacon-enable mode */
#define BEACON_FRAME_CREATION_INT_CLOCK_TICKS	(US_TO_SEC(CSMA_DEFAULT_TS_BI*CLOCK_CONF_SECOND))
#define BEACON_INT_INACTIVE_PERIOD				(US_TO_SEC((CSMA_DEFAULT_TS_BI - CSMA_DEFAULT_TS_SD)*CLOCK_CONF_SECOND))

#define US_TO_SEC(n)			((n)/1000000)

/* Is the BE PAN started */
int be_is_started = FALSE;
/* Has BE initialization failed? */
int be_is_initialized = FALSE;
/* Are we coordinator of the PAN-BE network? */
int be_is_coordinator = FALSE;
/* Are we associated to a PAN-BE network? */
int be_is_associated = FALSE;

/*Are we in the active period?*/
static int active_period = FALSE;
/*Flag that indicates next time slot the active period will start*/
static int prepare_for_active = FALSE;
/*Flag that indicates next time slot the active period will start*/
static int prepare_for_inactive = FALSE;


/* Current period for EB output */
static clock_time_t   beacon_interval_clk_ticks;
static rtimer_clock_t beacon_interval_rtimer_ticks;

#define MAX_QUEUED_PACKETS QUEUEBUF_NUM
MEMB(neighbor_memb, struct neighbor_queue, CSMA_MAX_NEIGHBOR_QUEUES);
MEMB(packet_memb, struct rdc_buf_list, MAX_QUEUED_PACKETS);
MEMB(metadata_memb, struct qbuf_metadata, MAX_QUEUED_PACKETS);
LIST(neighbor_list);

PROCESS(keep_tsn_process, "PAN-BE: Keep information about time slot number during BE operation");
PROCESS(beacon_process, "PAN-BE: Beacon frame process");
PROCESS(main_process, "PAN-BE: main process");

static PT_THREAD(tsn_update(struct rtimer *t));
static struct pt tsn_update_pt;

static PT_THREAD(slot_operation(struct rtimer *t, void *ptr));
static struct pt slot_operation_pt;

/*
 *	Function prototypes
 */

static void 	send_queue_add_packet( const linkaddr_t *addr, mac_callback_t sent, void *ptr );

static uint8_t 	schedule_slot_operation(struct rtimer *tm,
		                                rtimer_clock_t ref_time,
										rtimer_clock_t offset);

static uint8_t tsn_update_schedule	(struct rtimer *tm,
									 rtimer_clock_t ref_time,
									 rtimer_clock_t offset);

static struct neighbor_queue * next_slot_nq	( const uint8_t tsn );

static uint8_t get_tsn_start_time	(rtimer_clock_t * tns_start_time);
static uint8_t get_tsn_value	 	(uint8_t * tsn);
static void    set_tsn_start_time	(const rtimer_clock_t tns_start_time);
static void    set_tsn_value		(const uint8_t tsn);
static void    rsync_tsn			(const uint8_t tsn_ref, const rtimer_clock_t now);
static void    reset_tsn			(void);


/*****************************************************************************
 * 							PUBLIC FUNCTIONS
 ****************************************************************************/
/*Set this node as a coordinator*/
void
set_coordinator(void)
{
	be_is_coordinator = TRUE;
}

/*Set this node as a coordinator*/
void
unset_coordinator(void)
{
	be_is_coordinator = FALSE;
}



/*****************************************************************************
 * 					 		TSN  Aux functions
 ****************************************************************************/
/* Returns the next active neighbor queue given the current TSN value,
 * the behavior is different for a PAN coordinator and for a RFD */

static struct neighbor_queue *
next_slot_nq ( const uint8_t tsn )
{
	struct neighbor_queue *n = NULL;

	if( (tsn > 0) && (tsn <= LAST_ACTIVE_TS) ){
		n = list_head(neighbor_list);
		while(n != NULL) {
				if(n->transmit_tsn == tsn) {
					return n;
				}
				n = list_item_next(n);
			}
	}

	return n;

}

static uint8_t
get_tsn_start_time(rtimer_clock_t * tsn_start_time)
{
	*tsn_start_time = current_tsn.tsn_start_time;
	return current_tsn.is_tsn_start_time_set;
}

static uint8_t
get_tsn_value(uint8_t * tsn)
{
	*tsn = current_tsn.tsn_value;
	return (current_tsn.tsn_value < 32); /*Is returning a valid tsn_value?*/

}

static void
set_tsn_start_time(const rtimer_clock_t tsn_start_time)
{
	current_tsn.tsn_start_time = tsn_start_time ;
	current_tsn.is_tsn_start_time_set = TRUE;
}

static void
set_tsn_value(const uint8_t tsn)
{
	current_tsn.tsn_value = tsn;
}

static void
rsync_tsn( const uint8_t tsn_ref, const rtimer_clock_t now )
{
	current_tsn.tsn_value = tsn_ref;
	current_tsn.tsn_start_time = now;
	current_tsn.is_tsn_start_time_set = TRUE;

}
static void
reset_tsn( void )
{
	current_tsn.tsn_value = TSN_INVALID;
	current_tsn.tsn_start_time = (rtimer_clock_t)0;
	current_tsn.is_tsn_start_time_set = FALSE;

}

static void
increment_tsn( const rtimer_clock_t next_tsn_start_value )
{
	current_tsn.tsn_value = (current_tsn.tsn_value + 1) % MAX_TSN_VALUE;
	current_tsn.tsn_start_time = next_tsn_start_value;
}
/*****************************************************************************
 * 							SCHEDULING FUNCTIONS
 ****************************************************************************/

/* Beacon frame init */
void
beacon_frame_init( void )
{
	memset((void*)(&beacon_frame),0,sizeof(struct queuebuf_data));
}

/* Setup BE as a coordinator */
static void
start_coordinator(void)
{
  frame802154_set_pan_id(IEEE802154_PANID);

  be_is_associated = TRUE;

  PRINTF("BE-PAN: starting as coordinator, PAN ID %x \n",
		  frame802154_get_pan_id());

  rsync_tsn(LAST_INACTIVE_TS, RTIMER_NOW());

}
/*---------------------------------------------------------------------------*/


static void packet_sent(void *ptr, int status, int num_transmissions);
#if 0
static void transmit_packet_list(void *ptr);
#endif

static void
packet_sent(void *ptr, int status, int num_transmissions)
{
#if 0
	struct neighbor_queue *n;
	struct rdc_buf_list *q;

	n = ptr;
	if(n == NULL) {
		return;
	}

	/* Find out what packet this callback refers to */
	for(q = list_head(n->queued_packet_list);
			q != NULL; q = list_item_next(q)) {
		if(queuebuf_attr(q->buf, PACKETBUF_ATTR_MAC_SEQNO) ==
				packetbuf_attr(PACKETBUF_ATTR_MAC_SEQNO)) {
			break;
		}
	}

	if(q == NULL) {
		PRINTF("csma: seqno %d not found\n",
				packetbuf_attr(PACKETBUF_ATTR_MAC_SEQNO));
		return;
	} else if(q->ptr == NULL) {
		PRINTF("csma: no metadata\n");
		return;
	}

	switch(status) {
	case MAC_TX_OK:
		PRINTF("MAC_TX_OK - ");
		/*tx_ok(q, n, num_transmissions);*/
		break;
	case MAC_TX_NOACK:
		PRINTF("MAC_TX_NOACK - ");
		/*noack(q, n, num_transmissions);*/
		break;
	case MAC_TX_COLLISION:
		PRINTF("MAC_TX_COLLISION - ");
		/*collision(q, n, num_transmissions);*/
		break;
	case MAC_TX_DEFERRED:
		PRINTF("MAC_TX_DEFERRED - ");
		break;
	default:
		PRINTF("tx_done() -");

		/*tx_done(status, q, n);*/
		break;
	}
#endif
}

/*---------------------------------------------------------------------------*/
/* Scanning protothread, called by be_process:
 * Listen until it receives a beacon frame and attempt to associate.
 */
PT_THREAD(beacon_scan(struct pt *pt))
{
  PT_BEGIN(pt);

  static struct etimer scan_timer;
  etimer_set(&scan_timer, CLOCK_SECOND / BE_ASSOCIATION_POLL_FREQUENCY);

  while (!be_is_associated && !be_is_coordinator)
  {
	  	frame802154_t frame;
	  	rtimer_clock_t t0;
		/* Try to associate */
		NETSTACK_RADIO.on();

		int is_packet_pending = NETSTACK_RADIO.pending_packet();

	    if(!is_packet_pending && NETSTACK_RADIO.receiving_packet()) {
	      /* If we are currently receiving a packet, wait until end of reception */
	      t0 = RTIMER_NOW();
	      BUSYWAIT_UNTIL_ABS((is_packet_pending = NETSTACK_RADIO.pending_packet()), t0, RTIMER_SECOND / 100);
	    }

		if(is_packet_pending)
		{
			/* Read packet */
			uint8_t* pBuf = (uint8_t *)packetbuf_dataptr();
			int len = NETSTACK_RADIO.read(packetbuf_dataptr(), packetbuf_remaininglen());

			frame802154_parse(pBuf, len, &frame);

			/*Simple association process*/
			/*TODO: Is it enough?*/

			if( ( FRAME802154_BEACONFRAME == frame.fcf.frame_type ) &&  	/*It is a beacon frame type */
				( FRAME802154_BEACONFRAME >= frame.fcf.frame_version ) ){ 	/* It is NOT an Enhanced beacon frame*/
				frame802154_set_pan_id( frame.src_pid );
				be_is_associated = TRUE;
				/*TODO: node_id is defined automatically in Cooja when a new mote is created*/
				PRINTF("Node associated to PAN id: %d successfully!", frame.src_pid);
			}

			// TODO: after parsing the beacon, find the required values
		}

	    if(be_is_associated) {
	      /* End of association, turn the radio off */
	      NETSTACK_RADIO.off();
	    } else if(!be_is_coordinator) {
	      /* Go back to scanning */
	      etimer_reset(&scan_timer);
	      PT_WAIT_UNTIL(pt, etimer_expired(&scan_timer));
	    }
	}

  PT_END(pt);
}

/*---------------------------------------------------------------------------*/
static
PT_THREAD(tx_slot(struct pt *pt, struct rtimer *t))
{

  PT_BEGIN(pt);


  if( current_tsn.tsn_value == 0 ){ /*Send Beacon*/
	  /* Copy to beacon frame to the radio buffer */
	  if( beacon_frame.len > 0 ){
		  NETSTACK_RADIO.on();
		  if( NETSTACK_RADIO.prepare(beacon_frame.data, beacon_frame.len) == 0 ){ /* 0 means success */
			  //TSN_SCHEDULE_AND_YIELD(pt, t, current_tsn.tsn_start_time, csma_timing[csma_ts_send_beacon_guard]);
			  NETSTACK_RADIO.transmit(beacon_frame.len);
		  }
		  else{
			  /*Error handling*/
		  }
	  }
  }else if(current_tsn.tsn_value < 16)
  {
	  /*Callback to send neighbor buffer*/
  }


  /*TSCH implementation*/
#if 0
  TSCH_DEBUG_TX_EVENT();

  /* First check if we have space to store a newly dequeued packet (in case of
   * successful Tx or Drop) */
  dequeued_index = ringbufindex_peek_put(&dequeued_ringbuf);
  if(dequeued_index != -1) {
    if(current_packet == NULL || current_packet->qb == NULL) {
      mac_tx_status = MAC_TX_ERR_FATAL;
    } else {
      /* packet payload */
      static void *packet;
#if LLSEC802154_ENABLED
      /* encrypted payload */
      static uint8_t encrypted_packet[TSCH_PACKET_MAX_LEN];
#endif /* LLSEC802154_ENABLED */
      /* packet payload length */
      static uint8_t packet_len;
      /* packet seqno */
      static uint8_t seqno;
      /* is this a broadcast packet? (wait for ack?) */
      static uint8_t is_broadcast;
      static rtimer_clock_t tx_start_time;

#if CCA_ENABLED
      static uint8_t cca_status;
#endif

      /* get payload */
      packet = queuebuf_dataptr(current_packet->qb);
      packet_len = queuebuf_datalen(current_packet->qb);
      /* is this a broadcast packet? (wait for ack?) */
      is_broadcast = current_neighbor->is_broadcast;
      /* read seqno from payload */
      seqno = ((uint8_t *)(packet))[2];
      /* if this is an EB, then update its Sync-IE */
      if(current_neighbor == n_eb) {
        packet_ready = tsch_packet_update_eb(packet, packet_len, current_packet->tsch_sync_ie_offset);
      } else {
        packet_ready = 1;
      }

#if LLSEC802154_ENABLED
      if(tsch_is_pan_secured) {
        /* If we are going to encrypt, we need to generate the output in a separate buffer and keep
         * the original untouched. This is to allow for future retransmissions. */
        int with_encryption = queuebuf_attr(current_packet->qb, PACKETBUF_ATTR_SECURITY_LEVEL) & 0x4;
        packet_len += tsch_security_secure_frame(packet, with_encryption ? encrypted_packet : packet, current_packet->header_len,
            packet_len - current_packet->header_len, &tsch_current_asn);
        if(with_encryption) {
          packet = encrypted_packet;
        }
      }
#endif /* LLSEC802154_ENABLED */

      /* prepare packet to send: copy to radio buffer */
      if(packet_ready && NETSTACK_RADIO.prepare(packet, packet_len) == 0) { /* 0 means success */
        static rtimer_clock_t tx_duration;

#if CCA_ENABLED
        cca_status = 1;
        /* delay before CCA */
        TSCH_SCHEDULE_AND_YIELD(pt, t, current_slot_start, TS_CCA_OFFSET, "cca");
        TSCH_DEBUG_TX_EVENT();
        tsch_radio_on(TSCH_RADIO_CMD_ON_WITHIN_TIMESLOT);
        /* CCA */
        BUSYWAIT_UNTIL_ABS(!(cca_status |= NETSTACK_RADIO.channel_clear()),
                           current_slot_start, TS_CCA_OFFSET + TS_CCA);
        TSCH_DEBUG_TX_EVENT();
        /* there is not enough time to turn radio off */
        /*  NETSTACK_RADIO.off(); */
        if(cca_status == 0) {
          mac_tx_status = MAC_TX_COLLISION;
        } else
#endif /* CCA_ENABLED */
        {
          /* delay before TX */
          TSCH_SCHEDULE_AND_YIELD(pt, t, current_slot_start, tsch_timing[tsch_ts_tx_offset] - RADIO_DELAY_BEFORE_TX, "TxBeforeTx");
          TSCH_DEBUG_TX_EVENT();
          /* send packet already in radio tx buffer */
          mac_tx_status = NETSTACK_RADIO.transmit(packet_len);
          /* Save tx timestamp */
          tx_start_time = current_slot_start + tsch_timing[tsch_ts_tx_offset];
          /* calculate TX duration based on sent packet len */
          tx_duration = TSCH_PACKET_DURATION(packet_len);
          /* limit tx_time to its max value */
          tx_duration = MIN(tx_duration, tsch_timing[tsch_ts_max_tx]);
          /* turn tadio off -- will turn on again to wait for ACK if needed */
          tsch_radio_off(TSCH_RADIO_CMD_OFF_WITHIN_TIMESLOT);

          if(mac_tx_status == RADIO_TX_OK) {
            if(!is_broadcast) {
              uint8_t ackbuf[TSCH_PACKET_MAX_LEN];
              int ack_len;
              rtimer_clock_t ack_start_time;
              int is_time_source;
              struct ieee802154_ies ack_ies;
              uint8_t ack_hdrlen;
              frame802154_t frame;

#if TSCH_HW_FRAME_FILTERING
              radio_value_t radio_rx_mode;
              /* Entering promiscuous mode so that the radio accepts the enhanced ACK */
              NETSTACK_RADIO.get_value(RADIO_PARAM_RX_MODE, &radio_rx_mode);
              NETSTACK_RADIO.set_value(RADIO_PARAM_RX_MODE, radio_rx_mode & (~RADIO_RX_MODE_ADDRESS_FILTER));
#endif /* TSCH_HW_FRAME_FILTERING */
              /* Unicast: wait for ack after tx: sleep until ack time */
              TSCH_SCHEDULE_AND_YIELD(pt, t, current_slot_start,
                  tsch_timing[tsch_ts_tx_offset] + tx_duration + tsch_timing[tsch_ts_rx_ack_delay] - RADIO_DELAY_BEFORE_RX, "TxBeforeAck");
              TSCH_DEBUG_TX_EVENT();
              tsch_radio_on(TSCH_RADIO_CMD_ON_WITHIN_TIMESLOT);
              /* Wait for ACK to come */
              BUSYWAIT_UNTIL_ABS(NETSTACK_RADIO.receiving_packet(),
                  tx_start_time, tx_duration + tsch_timing[tsch_ts_rx_ack_delay] + tsch_timing[tsch_ts_ack_wait] + RADIO_DELAY_BEFORE_DETECT);
              TSCH_DEBUG_TX_EVENT();

              ack_start_time = RTIMER_NOW() - RADIO_DELAY_BEFORE_DETECT;

              /* Wait for ACK to finish */
              BUSYWAIT_UNTIL_ABS(!NETSTACK_RADIO.receiving_packet(),
                                 ack_start_time, tsch_timing[tsch_ts_max_ack]);
              TSCH_DEBUG_TX_EVENT();
              tsch_radio_off(TSCH_RADIO_CMD_OFF_WITHIN_TIMESLOT);

#if TSCH_HW_FRAME_FILTERING
              /* Leaving promiscuous mode */
              NETSTACK_RADIO.get_value(RADIO_PARAM_RX_MODE, &radio_rx_mode);
              NETSTACK_RADIO.set_value(RADIO_PARAM_RX_MODE, radio_rx_mode | RADIO_RX_MODE_ADDRESS_FILTER);
#endif /* TSCH_HW_FRAME_FILTERING */

              /* Read ack frame */
              ack_len = NETSTACK_RADIO.read((void *)ackbuf, sizeof(ackbuf));

              is_time_source = 0;
              /* The radio driver should return 0 if no valid packets are in the rx buffer */
              if(ack_len > 0) {
                is_time_source = current_neighbor != NULL && current_neighbor->is_time_source;
                if(tsch_packet_parse_eack(ackbuf, ack_len, seqno,
                    &frame, &ack_ies, &ack_hdrlen) == 0) {
                  ack_len = 0;
                }

#if LLSEC802154_ENABLED
                if(ack_len != 0) {
                  if(!tsch_security_parse_frame(ackbuf, ack_hdrlen, ack_len - ack_hdrlen - tsch_security_mic_len(&frame),
                      &frame, &current_neighbor->addr, &tsch_current_asn)) {
                    TSCH_LOG_ADD(tsch_log_message,
                        snprintf(log->message, sizeof(log->message),
                        "!failed to authenticate ACK"));
                    ack_len = 0;
                  }
                } else {
                  TSCH_LOG_ADD(tsch_log_message,
                      snprintf(log->message, sizeof(log->message),
                      "!failed to parse ACK"));
                }
#endif /* LLSEC802154_ENABLED */
              }

              if(ack_len != 0) {
                if(is_time_source) {
                  int32_t eack_time_correction = US_TO_RTIMERTICKS(ack_ies.ie_time_correction);
                  int32_t since_last_timesync = TSCH_ASN_DIFF(tsch_current_asn, last_sync_asn);
                  if(eack_time_correction > SYNC_IE_BOUND) {
                    drift_correction = SYNC_IE_BOUND;
                  } else if(eack_time_correction < -SYNC_IE_BOUND) {
                    drift_correction = -SYNC_IE_BOUND;
                  } else {
                    drift_correction = eack_time_correction;
                  }
                  if(drift_correction != eack_time_correction) {
#if 0
                    TSCH_LOG_ADD(tsch_log_message,
                        snprintf(log->message, sizeof(log->message),
                            "!truncated dr %d %d", (int)eack_time_correction, (int)drift_correction);
                    );
#endif
                  }
                  is_drift_correction_used = 1;
                  tsch_timesync_update(current_neighbor, since_last_timesync, drift_correction);
                  /* Keep track of sync time */
                  last_sync_asn = tsch_current_asn;
                  tsch_schedule_keepalive();
                }
                mac_tx_status = MAC_TX_OK;
              } else {
                mac_tx_status = MAC_TX_NOACK;
              }
            } else {
              mac_tx_status = MAC_TX_OK;
            }
          } else {
            mac_tx_status = MAC_TX_ERR;
          }
        }
      }
    }

    tsch_radio_off(TSCH_RADIO_CMD_OFF_END_OF_TIMESLOT);

    current_packet->transmissions++;
    current_packet->ret = mac_tx_status;

    /* Post TX: Update neighbor state */
    in_queue = update_neighbor_state(current_neighbor, current_packet, current_link, mac_tx_status);

    /* The packet was dequeued, add it to dequeued_ringbuf for later processing */
    if(in_queue == 0) {
      dequeued_array[dequeued_index] = current_packet;
      ringbufindex_put(&dequeued_ringbuf);
    }

    /* Log every tx attempt */
#if 0
    TSCH_LOG_ADD(tsch_log_tx,
        log->tx.mac_tx_status = mac_tx_status;
    log->tx.num_tx = current_packet->transmissions;
    log->tx.datalen = queuebuf_datalen(current_packet->qb);
    log->tx.drift = drift_correction;
    log->tx.drift_used = is_drift_correction_used;
    log->tx.is_data = ((((uint8_t *)(queuebuf_dataptr(current_packet->qb)))[0]) & 7) == FRAME802154_DATAFRAME;
#if LLSEC802154_ENABLED
    log->tx.sec_level = queuebuf_attr(current_packet->qb, PACKETBUF_ATTR_SECURITY_LEVEL);
#else /* LLSEC802154_ENABLED */
    log->tx.sec_level = 0;
#endif /* LLSEC802154_ENABLED */
    log->tx.dest = TSCH_LOG_ID_FROM_LINKADDR(queuebuf_addr(current_packet->qb, PACKETBUF_ADDR_RECEIVER));
    );
#endif

    /* Poll process for later processing of packet sent events and logs */
    process_poll(&tsch_pending_events_process);
  }

  TSCH_DEBUG_TX_EVENT();
#endif
  PT_END(pt);
}

/*---------------------------------------------------------------------------*/
static void
be_reset(void)
{
  int i;

  reset_tsn();
  /* Reset timeslot timing to defaults */
  for(i = 0; i < csma_ts_elements_count; i++) {
    csma_timing[i] = US_TO_RTIMERTICKS(csma_default_timing_us[i]);
  }

}

static
PT_THREAD(rx_slot(struct pt *pt, struct rtimer *t))
{
  /**
   * RX slot:
   * 1. Check if it is used for TIME_KEEPING
   * 2. Sleep and wake up just before expected RX time (with a guard time: TS_LONG_GT)
   * 3. Check for radio activity for the guard time: TS_LONG_GT
   * 4. Prepare and send ACK if needed
   * 5. Drift calculated in the ACK callback registered with the radio driver. Use it if receiving from a time source neighbor.
   **/
#if 0
  struct tsch_neighbor *n;
  static linkaddr_t source_address;
  static linkaddr_t destination_address;
  static int16_t input_index;
  static int input_queue_drop = 0;
#endif
  PT_BEGIN(pt);

  /*TSH implementation*/
#if 0
  TSCH_DEBUG_RX_EVENT();

  input_index = ringbufindex_peek_put(&input_ringbuf);
  if(input_index == -1) {
    input_queue_drop++;
  } else {
    static struct input_packet *current_input;
    /* Estimated drift based on RX time */
    static int32_t estimated_drift;
    /* Rx timestamps */
    static rtimer_clock_t rx_start_time;
    static rtimer_clock_t expected_rx_time;
    static rtimer_clock_t packet_duration;
    uint8_t packet_seen;

    expected_rx_time = current_slot_start + tsch_timing[tsch_ts_tx_offset];
    /* Default start time: expected Rx time */
    rx_start_time = expected_rx_time;

    current_input = &input_array[input_index];

    /* Wait before starting to listen */
    TSCH_SCHEDULE_AND_YIELD(pt, t, current_slot_start, tsch_timing[tsch_ts_rx_offset] - RADIO_DELAY_BEFORE_RX, "RxBeforeListen");
    TSCH_DEBUG_RX_EVENT();

    /* Start radio for at least guard time */
    tsch_radio_on(BE_RADIO_CMD_ON_WITHIN_TIMESLOT);
    packet_seen = NETSTACK_RADIO.receiving_packet() || NETSTACK_RADIO.pending_packet();
    if(!packet_seen) {
      /* Check if receiving within guard time */
      BUSYWAIT_UNTIL_ABS((packet_seen = NETSTACK_RADIO.receiving_packet()),
          current_slot_start, tsch_timing[tsch_ts_rx_offset] + tsch_timing[tsch_ts_rx_wait] + RADIO_DELAY_BEFORE_DETECT);
    }
    if(!packet_seen) {
      /* no packets on air */
      tsch_radio_off(BE_RADIO_CMD_OFF_FORCE);
    } else {
      TSCH_DEBUG_RX_EVENT();
      /* Save packet timestamp */
      rx_start_time = RTIMER_NOW() - RADIO_DELAY_BEFORE_DETECT;

      /* Wait until packet is received, turn radio off */
      BUSYWAIT_UNTIL_ABS(!NETSTACK_RADIO.receiving_packet(),
          current_slot_start, tsch_timing[tsch_ts_rx_offset] + tsch_timing[tsch_ts_rx_wait] + tsch_timing[tsch_ts_max_tx]);
      TSCH_DEBUG_RX_EVENT();
      tsch_radio_off(BE_RADIO_CMD_OFF_WITHIN_TIMESLOT);

      if(NETSTACK_RADIO.pending_packet()) {
        static int frame_valid;
        static int header_len;
        static frame802154_t frame;
        radio_value_t radio_last_rssi;

        /* Read packet */
        current_input->len = NETSTACK_RADIO.read((void *)current_input->payload, TSCH_PACKET_MAX_LEN);
        NETSTACK_RADIO.get_value(RADIO_PARAM_LAST_RSSI, &radio_last_rssi);
        current_input->rx_asn = tsch_current_asn;
        current_input->rssi = (signed)radio_last_rssi;
        current_input->channel = current_channel;
        header_len = frame802154_parse((uint8_t *)current_input->payload, current_input->len, &frame);
        frame_valid = header_len > 0 &&
          frame802154_check_dest_panid(&frame) &&
          frame802154_extract_linkaddr(&frame, &source_address, &destination_address);

#if TSCH_RESYNC_WITH_SFD_TIMESTAMPS
        /* At the end of the reception, get an more accurate estimate of SFD arrival time */
        NETSTACK_RADIO.get_object(RADIO_PARAM_LAST_PACKET_TIMESTAMP, &rx_start_time, sizeof(rtimer_clock_t));
#endif

        packet_duration = TSCH_PACKET_DURATION(current_input->len);

#if LLSEC802154_ENABLED
#error LLSEC802154_ENABLED is not currently supported
#if 0
        /* Decrypt and verify incoming frame */
        if(frame_valid) {
          if(tsch_security_parse_frame(
               current_input->payload, header_len, current_input->len - header_len - tsch_security_mic_len(&frame),
               &frame, &source_address, &tsch_current_asn)) {
            current_input->len -= tsch_security_mic_len(&frame);
          } else {
            TSCH_LOG_ADD(tsch_log_message,
                snprintf(log->message, sizeof(log->message),
                "!failed to authenticate frame %u", current_input->len));
            frame_valid = 0;
          }
        } else {
          TSCH_LOG_ADD(tsch_log_message,
              snprintf(log->message, sizeof(log->message),
              "!failed to parse frame %u %u", header_len, current_input->len));
          frame_valid = 0;
        }
#endif
#endif /* LLSEC802154_ENABLED */

        if(frame_valid) {
          if(linkaddr_cmp(&destination_address, &linkaddr_node_addr)
             || linkaddr_cmp(&destination_address, &linkaddr_null)) {
            int do_nack = 0;
            estimated_drift = RTIMER_CLOCK_DIFF(expected_rx_time, rx_start_time);

#if TSCH_TIMESYNC_REMOVE_JITTER
            /* remove jitter due to measurement errors */
            if(ABS(estimated_drift) <= TSCH_TIMESYNC_MEASUREMENT_ERROR) {
              estimated_drift = 0;
            } else if(estimated_drift > 0) {
              estimated_drift -= TSCH_TIMESYNC_MEASUREMENT_ERROR;
            } else {
              estimated_drift += TSCH_TIMESYNC_MEASUREMENT_ERROR;
            }
#endif

#ifdef TSCH_CALLBACK_DO_NACK
            if(frame.fcf.ack_required) {
              do_nack = TSCH_CALLBACK_DO_NACK(current_link,
                  &source_address, &destination_address);
            }
#endif

            if(frame.fcf.ack_required) {
              static uint8_t ack_buf[TSCH_PACKET_MAX_LEN];
              static int ack_len;

              /* Build ACK frame */
              ack_len = tsch_packet_create_eack(ack_buf, sizeof(ack_buf),
                  &source_address, frame.seq, (int16_t)RTIMERTICKS_TO_US(estimated_drift), do_nack);

              if(ack_len > 0) {
#if LLSEC802154_ENABLED
                if(tsch_is_pan_secured) {
                  /* Secure ACK frame. There is only header and header IEs, therefore data len == 0. */
                  ack_len += tsch_security_secure_frame(ack_buf, ack_buf, ack_len, 0, &tsch_current_asn);
                }
#endif /* LLSEC802154_ENABLED */

                /* Copy to radio buffer */
                NETSTACK_RADIO.prepare((const void *)ack_buf, ack_len);

                /* Wait for time to ACK and transmit ACK */
                TSCH_SCHEDULE_AND_YIELD(pt, t, rx_start_time,
                                        packet_duration + tsch_timing[tsch_ts_tx_ack_delay] - RADIO_DELAY_BEFORE_TX, "RxBeforeAck");
                TSCH_DEBUG_RX_EVENT();
                NETSTACK_RADIO.transmit(ack_len);
                tsch_radio_off(BE_RADIO_CMD_OFF_WITHIN_TIMESLOT);
              }
            }

            /* If the sender is a time source, proceed to clock drift compensation */
            n = tsch_queue_get_nbr(&source_address);
            if(n != NULL && n->is_time_source) {
              int32_t since_last_timesync = TSCH_ASN_DIFF(tsch_current_asn, last_sync_asn);
              /* Keep track of last sync time */
              last_sync_asn = tsch_current_asn;
              /* Save estimated drift */
              drift_correction = -estimated_drift;
              is_drift_correction_used = 1;
              tsch_timesync_update(n, since_last_timesync, -estimated_drift);
              tsch_schedule_keepalive();
            }

            /* Add current input to ringbuf */
            ringbufindex_put(&input_ringbuf);

#if 0
            /* Log every reception */
            TSCH_LOG_ADD(tsch_log_rx,
              log->rx.src = TSCH_LOG_ID_FROM_LINKADDR((linkaddr_t*)&frame.src_addr);
              log->rx.is_unicast = frame.fcf.ack_required;
              log->rx.datalen = current_input->len;
              log->rx.drift = drift_correction;
              log->rx.drift_used = is_drift_correction_used;
              log->rx.is_data = frame.fcf.frame_type == FRAME802154_DATAFRAME;
              log->rx.sec_level = frame.aux_hdr.security_control.security_level;
              log->rx.estimated_drift = estimated_drift;
            );
          }
#endif
          /* Poll process for processing of pending input and logs */
          process_poll(&tsch_pending_events_process);
        }
      }

      tsch_radio_off(BE_RADIO_CMD_OFF_END_OF_TIMESLOT);
    }
    if(input_queue_drop != 0) {
#if 0
      TSCH_LOG_ADD(tsch_log_message,
          snprintf(log->message, sizeof(log->message),
              "!queue full skipped %u", input_queue_drop);
      );
#endif
      input_queue_drop = 0;
    }
  }

  TSCH_DEBUG_RX_EVENT();
#endif

  PT_END(pt);
}

/*---------------------------------------------------------------------------*/
/* Protothread for slot operation, called from rtimer interrupt
 * and scheduled from tsch_schedule_slot_operation */
static
PT_THREAD(slot_operation(struct rtimer *t, void *ptr))
{
  PT_BEGIN(&slot_operation_pt);

#if 0
  /* Loop over all active slots */
  while(tsch_is_associated) {

    if(current_link == NULL || tsch_lock_requested) { /* Skip slot operation if there is no link
                                                          or if there is a pending request for getting the lock */
#if 0
      /* Issue a log whenever skipping a slot */
      TSCH_LOG_ADD(tsch_log_message,
                      snprintf(log->message, sizeof(log->message),
                          "!skipped slot %u %u %u",
                            tsch_locked,
                            tsch_lock_requested,
                            current_link == NULL);
      );
#endif

    } else {
      int is_active_slot;
      TSCH_DEBUG_SLOT_START();
      be_in_slot_operation = 1;
      /* Reset drift correction */
      drift_correction = 0;
      is_drift_correction_used = 0;
      /* Get a packet ready to be sent */
      current_packet = get_packet_and_neighbor_for_link(current_link, &current_neighbor);
      /* There is no packet to send, and this link does not have Rx flag. Instead of doing
       * nothing, switch to the backup link (has Rx flag) if any. */
      if(current_packet == NULL && !(current_link->link_options & LINK_OPTION_RX) && backup_link != NULL) {
        current_link = backup_link;
        current_packet = get_packet_and_neighbor_for_link(current_link, &current_neighbor);
      }
      is_active_slot = current_packet != NULL || (current_link->link_options & LINK_OPTION_RX);
      if(is_active_slot) {
        /* Hop channel */
        current_channel = tsch_calculate_channel(&tsch_current_asn, current_link->channel_offset);
        NETSTACK_RADIO.set_value(RADIO_PARAM_CHANNEL, current_channel);
        /* Turn the radio on already here if configured so; necessary for radios with slow startup */
        tsch_radio_on(BE_RADIO_CMD_ON_START_OF_TIMESLOT);
        /* Decide whether it is a TX/RX/IDLE or OFF slot */
        /* Actual slot operation */
        if(current_packet != NULL) {
          /* We have something to transmit, do the following:
           * 1. send
           * 2. update_backoff_state(current_neighbor)
           * 3. post tx callback
           **/
          static struct pt slot_tx_pt;
          PT_SPAWN(&slot_operation_pt, &slot_tx_pt, tx_slot(&slot_tx_pt, t));
        } else {
          /* Listen */
          static struct pt slot_rx_pt;
          PT_SPAWN(&slot_operation_pt, &slot_rx_pt, rx_slot(&slot_rx_pt, t));
        }
      }
    }

    /* End of slot operation, schedule next slot or resynchronize */

    /* Do we need to resynchronize? i.e., wait for EB again */
    if(!tsch_is_coordinator && (TSCH_ASN_DIFF(tsch_current_asn, last_sync_asn) >
        (100 * TSCH_CLOCK_TO_SLOTS(TSCH_DESYNC_THRESHOLD / 100, tsch_timing[tsch_ts_timeslot_length])))) {
#if 0
      TSCH_LOG_ADD(tsch_log_message,
            snprintf(log->message, sizeof(log->message),
                "! leaving the network, last sync %u",
                          (unsigned)TSCH_ASN_DIFF(tsch_current_asn, last_sync_asn));
      );
#endif
      last_timesource_neighbor = NULL;
      tsch_disassociate();
    } else {
      /* backup of drift correction for printing debug messages */
      /* int32_t drift_correction_backup = drift_correction; */
      uint16_t timeslot_diff = 0;
      rtimer_clock_t prev_slot_start;
      /* Time to next wake up */
      rtimer_clock_t time_to_next_active_slot;
      /* Schedule next wakeup skipping slots if missed deadline */
      do {
        if(current_link != NULL
            && current_link->link_options & LINK_OPTION_TX
            && current_link->link_options & LINK_OPTION_SHARED) {
          /* Decrement the backoff window for all neighbors able to transmit over
           * this Tx, Shared link. */
          tsch_queue_update_all_backoff_windows(&current_link->addr);
        }

        /* Get next active link */
        current_link = tsch_schedule_get_next_active_link(&tsch_current_asn, &timeslot_diff, &backup_link);
        if(current_link == NULL) {
          /* There is no next link. Fall back to default
           * behavior: wake up at the next slot. */
          timeslot_diff = 1;
        }
        /* Update ASN */
        TSCH_ASN_INC(tsch_current_asn, timeslot_diff);
        /* Time to next wake up */
        time_to_next_active_slot = timeslot_diff * tsch_timing[tsch_ts_timeslot_length] + drift_correction;
        drift_correction = 0;
        is_drift_correction_used = 0;
        /* Update current slot start */
        prev_slot_start = current_slot_start;
        current_slot_start += time_to_next_active_slot;
        current_slot_start += tsch_timesync_adaptive_compensate(time_to_next_active_slot);
      } while(!tsch_schedule_slot_operation(t, prev_slot_start, time_to_next_active_slot, "main"));
    }

    tsch_in_slot_operation = 0;
    PT_YIELD(&slot_operation_pt);
  }
#endif

  PT_END(&slot_operation_pt);
}
int
beacon_packet_create( uint8_t *buf, int buf_size )
{
  uint8_t curr_len = 0;

  frame802154_t p;

  /* Create 802.15.4 header */
  memset(&p, 0, sizeof(p));
  p.fcf.frame_type = FRAME802154_BEACONFRAME;
  p.fcf.ie_list_present = 0;
  p.fcf.frame_version = FRAME802154_IEEE802154_2006;
  p.fcf.src_addr_mode = LINKADDR_SIZE > 2 ? FRAME802154_LONGADDRMODE : FRAME802154_SHORTADDRMODE;
  p.fcf.dest_addr_mode = FRAME802154_SHORTADDRMODE;
  p.fcf.sequence_number_suppression = 1;
  /* It is important not to compress PAN ID, as this would result in not including either
   * source nor destination PAN ID, leaving potential joining devices unaware of the PAN ID. */
  p.fcf.panid_compression = 0;

  p.superframe_spec.panCoord = TRUE;
  p.superframe_spec.beaconOrder = DEFAULT_BO;
  p.superframe_spec.superframeOrder = DEFAULT_SO;

  p.src_pid = frame802154_get_pan_id();
  p.dest_pid = frame802154_get_pan_id();
  linkaddr_copy((linkaddr_t *)&p.src_addr, &linkaddr_node_addr);
  p.dest_addr[0] = 0xff;
  p.dest_addr[1] = 0xff;

  curr_len = frame802154_create(&p, buf);


  return curr_len;
}
/*---------------------------------------------------------------------------*/
/* Timing utility functions */

/* Checks if the current time has passed a ref time + offset. Assumes
 * a single overflow and ref time prior to now. */
static uint8_t
check_timer_miss(rtimer_clock_t ref_time, rtimer_clock_t offset, rtimer_clock_t now)
{
  rtimer_clock_t target = ref_time + offset;
  int now_has_overflowed = now < ref_time;
  int target_has_overflowed = target < ref_time;

  if(now_has_overflowed == target_has_overflowed) {
    /* Both or none have overflowed, just compare now to the target */
    return target <= now;
  } else {
    /* Either now or target of overflowed.
     * If it is now, then it has passed the target.
     * If it is target, then we haven't reached it yet.
     *  */
    return now_has_overflowed;
  }
}
/*---------------------------------------------------------------------------*/
/* Schedule a wakeup at a specified offset from a reference time.
 * Provides basic protection against missed deadlines and timer overflows
 * A return value of zero signals a missed deadline: no rtimer was scheduled. */
static uint8_t
schedule_slot_operation(struct rtimer *tm, rtimer_clock_t ref_time, rtimer_clock_t offset)
{
#if 0
  rtimer_clock_t now = RTIMER_NOW();
  int r;
  /* Subtract RTIMER_GUARD before checking for deadline miss
   * because we can not schedule rtimer less than RTIMER_GUARD in the future */
  int missed = check_timer_miss(ref_time, offset - RTIMER_GUARD, now);

  if(missed) {
    return 0;
  }
  ref_time += offset;
  r = rtimer_set(tm, ref_time, 1, (void (*)(struct rtimer *, void *))slot_operation, NULL);
  if(r != RTIMER_OK) {
    return 0;
  }
#endif
  return 1;
}

/* Set global time before starting slot operation,
 * with a rtimer time */
void
slot_operation_start(void)
{
#if 0
  static struct rtimer slot_operation_timer;
  rtimer_clock_t time_to_next_active_slot;
  rtimer_clock_t prev_slot_start;

  do {
    uint16_t timeslot_diff;
    /* Get next active link */
    /*TODO: Do we need something like this?*/

    current_link = schedule_get_next_active_link(&timeslot_diff);

    if(current_link == NULL) {
      /* There is no next link. Fall back to default
       * behavior: wake up at the next slot. */
      timeslot_diff = 1;
    }
    /* Time to next wake up */
    time_to_next_active_slot = timeslot_diff * tsch_timing[tsch_ts_timeslot_length];
    /* Update current slot start */
    prev_slot_start = current_slot_start;
    current_slot_start += time_to_next_active_slot;
  } while(!schedule_slot_operation(&slot_operation_timer, prev_slot_start, time_to_next_active_slot, "association"));
#endif
}

/*
 * Description: A periodic process to send beacon frames when using Beacon-Enabled (BE) mode.
 *
 * PAN-coordinator:
 * 		Infinite loop:
 * 			1. Prepare beacon frame packet.
 * 			2. Load beacon frame to a neighbor queue.
 * 			3. Set rtimer_set to call "send_beacon_frame()" in time_to_send_beacon rticks,
 * 			   that function will take care of setting the BI_init_time of the next beacon interval.
 * 			4. Set an etimer to wait until we get closer to the inactive period.
 * 			5. Set a rtimer_set to call "end_active_period()" in active_period_left_time in rticks.
 * 			6. Set an etimer to wait until we get closer to the next active period.
 *
 *
 * 	RFD:
 * 		Infinite loop:
 * 			1. Scan_beacon(), if received, calculate BI_init time and set active_period to TRUE
 *				1.1. Set an etimer to wait until we get closer to the inactive period.
 *				1.2. Set a rtimer_set to call "end_active_period()" in active_period_left_time in rticks.
 * 				1.3. Set an etimer to wait until we get closer to the next active period.
 * 			2. If we don't receive beacon after a while, disassociate from the network and wait for a
 * 			   beacon again, do not transmit until receive it.
 *
 *
 * */
PROCESS_THREAD(beacon_process, ev, data)
{
	static struct etimer be_timer;
	frame802154_t pf;
	int i = 0;

	PROCESS_BEGIN();

	/* Set the timer to send beacons periodically */
	etimer_set(&be_timer, (clock_time_t)(BEACON_FRAME_CREATION_INT_CLOCK_TICKS));

	while( _ALWAYS_ )
	{
		if( be_is_associated ){
			if(be_is_coordinator)
			{
				int beacon_len;
				int radioTxStatus;

				/* Prepare the EB packet and schedule it to be sent */
				packetbuf_clear();
				packetbuf_set_attr(PACKETBUF_ATTR_FRAME_TYPE, FRAME802154_BEACONFRAME);

				beacon_len = beacon_packet_create( (uint8_t *)packetbuf_dataptr(), (int)PACKETBUF_SIZE );

				if( beacon_len == 0 ){
					PRINTF("Beacon frame create failed!\n");
					break;
				}

				packetbuf_set_datalen(beacon_len);

				/*Just put beacon frame on send beacon frame queue, it will be processed during slotted CSMA operation*/
				beacon_frame_init();
				beacon_frame.len = packetbuf_copyto(beacon_frame.data);
				packetbuf_attr_copyto(beacon_frame.attrs, beacon_frame.addrs);

				etimer_reset(&be_timer);
				PROCESS_WAIT_UNTIL(etimer_expired(&be_timer));

			}
			else
			{
				/*RFD logic*/
			}

		}
	}
#if 0
	while(1)
	{
		if (!is_coordinator)
		{
			/* Non-Coordinator */
			NETSTACK_RADIO.on();

			int is_packet_pending = NETSTACK_RADIO.pending_packet();

			if(is_packet_pending)
			{
				/* Read packet */
				char* pBuf = packetbuf_dataptr();
				int len = NETSTACK_RADIO.read(packetbuf_dataptr(), 127);
				PRINTF("PAcket Received len: %d\n",len);

				frame802154_parse(pBuf, len, &pf);
				PRINTF("Dest addr(1): %x\n", pf.fcf.frame_version);
				//PRINTF("Frame Type(0): %x \n", pf.fcf.frame_type);
				//PRINTF("Dest addr0(0xff): %d\n", pf.dest_addr[0]);
				//PRINTF("Dest addr1(0xff): %d\n", pf.dest_addr[1]);

				// TODO: after parsing the beacon, find the required values
			}
		}
		else
		{
			/* Coordinator */
			int beacon_len;
			int radioTxStatus;

			/* Prepare the EB packet and schedule it to be sent */
			packetbuf_clear();
			packetbuf_set_attr(PACKETBUF_ATTR_FRAME_TYPE, FRAME802154_BEACONFRAME);

			beacon_len = be_packet_create_beacon( (uint8_t *)packetbuf_dataptr(), (int)PACKETBUF_SIZE );

			if( beacon_len > 0 )
			{
				packetbuf_set_datalen(beacon_len);
			}

			NETSTACK_RADIO.on();
			radioTxStatus = NETSTACK_RADIO.send(packetbuf_dataptr(),packetbuf_datalen());
			PRINTF("Data length: %u\n", packetbuf_datalen());

			PRINTF("Radio send status: \n");
			switch( radioTxStatus )
			{
			case RADIO_TX_OK:
				PRINTF("RADIO_TX_OK");
				break;
			case RADIO_TX_ERR:
				PRINTF("RADIO_TX_ERR");
				break;
			case RADIO_TX_COLLISION:
				PRINTF("RADIO_TX_COLLISION");
				break;
			case RADIO_TX_NOACK:
				PRINTF("RADIO_TX_COLLISION");
				break;
			default:
				PRINTF("RADIO_TX_UNKNOWN");
			}

			NETSTACK_RADIO.off();

			/* Set the timer to send beacons periodically */
			etimer_set(&be_timer, (clock_time_t)BE_SF_DEFAULT_PERIOD);
			PROCESS_WAIT_UNTIL(etimer_expired(&be_timer));
		}
	}

#endif

	PROCESS_END();
}
/* Protothread for updating TSN information, called from rtimer interrupt
 * and scheduled from tsn_update_schedule */
static
PT_THREAD(tsn_update(struct rtimer *t))
{
  uint8_t scheduled = FALSE;
  uint8_t curr_tsn = TSN_INVALID;
  uint8_t is_valid_tsn = FALSE;
  rtimer_clock_t curr_start_time = 0;
  rtimer_clock_t time_to_next_ts = 0;

  PT_BEGIN(&tsn_update_pt);


  while( be_is_associated )
  {
	  increment_tsn( RTIMER_NOW() );

	  is_valid_tsn = get_tsn_start_time(&curr_start_time) && get_tsn_value(&curr_tsn);
	  if( is_valid_tsn == TRUE ){
		  if( curr_tsn == 0 ){ /*Beacon Frame*/
			  active_period = TRUE;
			  NETSTACK_RADIO.on();
			  if( be_is_coordinator ){
				  /*send_beacon task spawn*/
				  static struct pt slot_tx_pt;
				  PT_SPAWN(&tsn_update_pt, &slot_tx_pt, tx_slot(&slot_tx_pt, t));
			  }
			  else{
				  /*read_beacon_task_spawn*/
			  }
		  }else if( (curr_tsn <= LAST_ACTIVE_TS) )
		  {
			  if(nq != NULL) {
				/* We have something to transmit, do the following:
				 * 1. send
				 * 2. post tx callback
				 **/
				static struct pt slot_tx_pt;
				PT_SPAWN(&tsn_update_pt, &slot_tx_pt, tx_slot(&slot_tx_pt, t));
			  } else {
				/* Listen ?*/
#if 0
				static struct pt slot_rx_pt;
				PT_SPAWN(&tsn_update_pt, &slot_rx_pt, rx_slot(&slot_rx_pt, t));
#endif
			  }
		  }


		  if(curr_tsn == LAST_ACTIVE_TS ){
			  prepare_for_inactive = TRUE;
		  }else if( curr_tsn == FIRST_INACTIVE_TS ){
			  active_period = FALSE;
			  NETSTACK_RADIO.off();
		  }else if( curr_tsn == LAST_INACTIVE_TS){
			  prepare_for_active = TRUE;
		  }

		  if( curr_tsn < 16 ){
			  time_to_next_ts = csma_timing[csma_ts_active_length];
		  }else{
			  time_to_next_ts = csma_timing[csma_ts_active_length];
		  }

		  if( curr_tsn == LAST_INACTIVE_TS){
			  time_to_next_ts -= csma_timing[csma_ts_send_beacon_guard];
		  }

		  /*Do we have something to send in the next time slot?*/
		  nq = next_slot_nq( (curr_tsn + 1) % MAX_TSN_VALUE );

		  scheduled = tsn_update_schedule(t, curr_start_time, time_to_next_ts);

		  if(!scheduled){
			  /*Error handling*/
		  }

	  }
	  PT_YIELD(&tsn_update_pt);
  }

  PT_END(&tsn_update_pt);
}

static uint8_t
tsn_update_schedule(struct rtimer *tm, rtimer_clock_t ref_time, rtimer_clock_t offset)
{
	int r;
	rtimer_clock_t now = RTIMER_NOW();
	int missed = check_timer_miss(ref_time, offset - RTIMER_GUARD, now);

	PRINTF("TSN_sch: %d, rtimer=%u\n",current_tsn.tsn_value, current_tsn.tsn_start_time);
	if(missed) {
	  PRINTF(" !\n");
	  return 0;
	}
	ref_time += offset;
	r = rtimer_set(tm, ref_time , 1, (void (*)(struct rtimer *))tsn_update, NULL);
	if(r != RTIMER_OK) {
		return 0;
	}
	return 1;
}

static void
tsn_update_start( void )
{
	static struct rtimer tsn_update_timer;
	rtimer_clock_t time_to_next_ts;
	rtimer_clock_t prev_ts_start;
	uint8_t curr_tns;

	PRINTF("tsn_update_start\n");

	do{
		PRINTF("*\n");
		time_to_next_ts = csma_timing[csma_ts_active_length];
		PRINTF("*\n");
		if( !get_tsn_value(&curr_tns) || !get_tsn_start_time(&prev_ts_start) ){
			PRINTF("!\n");
			return;	/*Invalid TNS or start time value*/
		}
		PRINTF("*\n");
	}while( !tsn_update_schedule(&tsn_update_timer, prev_ts_start, time_to_next_ts) );
}

/* Process to keep TSN data updated */

/*
 *	Description: This process is taking care of updating the current TSN value and initial time
 *	             (rtimer_clock_t). All this information is stored in a struct tsn_t
 *
 *	             It does nothing until be_is_associated is true.
 *
 *	             active_period   -> 0  <= tsn_value < 16
 *	             inactive_period -> 16 < tsn_value < 32
 *
 *	Steps:
 *		1. While !be_is_associated, wait one clock_t using etimer.
 *		2. Call start_tsn_update().
 *		3. Yield until (!be_is_associated), it means we need to sync and start again.
 *
 *
 *
 *
 */

PROCESS_THREAD(keep_tsn_process, ev, data){

	static struct etimer tsn_timer;
	static rtimer_clock_t curr_start_time;
	static curr_tsn = TSN_INVALID;

	PROCESS_BEGIN();
	/* Set the timer to send beacons periodically */
	etimer_set(&tsn_timer, (clock_time_t)(1));

	PRINTF("TNS_PROCESS\n");

	while(_ALWAYS_){
		while(!be_is_associated){
			if(be_is_coordinator) {
				/* We are coordinator, start operating now */
				start_coordinator();
			} else {
				/* Start scanning, will attempt to join when receiving an EB */
				static struct pt scan_pt;
				PROCESS_PT_SPAWN(&scan_pt, beacon_scan(&scan_pt));
			}
			etimer_reset(&tsn_timer);
			PROCESS_WAIT_UNTIL(etimer_expired(&tsn_timer));
		}

		tsn_update_start();

		/* Yield our keep_tsn process. tsn_update will schedule itself as long as
		 * we keep associated */
		 PROCESS_YIELD_UNTIL(!be_is_associated);

		/*TODO: Do we need some cleanup here?*/
	}

	PROCESS_END();
}
/* The main process */


/*
 *  Association: First action is to ensure that we get associated to a network, if this node is a
 *               coordinator we just need to set PAN ID parameters, if it is a RFD, need to wait
 *               for a beacon frame to arrive.
 *
 *
 * 	PAN-Coordinator: Only receives data and pass it to upper layers, if we have RX_POLL disabled,
 * 	                 we don't need to do anything else since it will be handled automatically
 * 	                 by the radio layer when a packet arrives.
 *
 * 	                 We need to evaluate if we need to configure the RADIO RX in poll mode during
 * 	                 the timeslot 0 when we expect to receive a beacon frame to avoid passing
 * 	                 that input frame to upper layers.
 *
 * 	RFD: After a successful association process we need to:
 * 		1. Yield process until active_period is TRUE
 * 		2. Call start_slot_op()
 * 		3. Yield until active_period is false. This means that now we just need to wait
 * 		   for the next beacon frame.
 * 		4. Yield until wait_for_beacon is TRUE, this flag is activated "some ms after" we expect
 * 		   to receive a beacon frame.
 * 		5. scan_beacon() procedure, can we define a new or reuse the existing protothread to do this?
 * 		6. Go back to step 1
 *
 *   slot_operation:
 * 				1.1. if time slot number (TSN) is zero, we are in the beacon time slot.
 * 					1.1.2 Get next TSN active and schedule  wakeup in that TSN.
 * 					1.1.3 If not TSN active found, go to default behavior and schedule a wakeup TSN+1
 * 				1.2. if (TSN != 0)
 * 					1.2.1
 *
 */
PROCESS_THREAD(main_process, ev, data)
{
  static struct pt scan_pt;

  PROCESS_BEGIN();

  while(_ALWAYS_) {

    while(!be_is_associated) {
      if(be_is_coordinator) {
        /* We are coordinator, start operating now */
        start_coordinator();
      } else {
        /* Start scanning, will attempt to join when receiving an EB */
        PROCESS_PT_SPAWN(&scan_pt, beacon_scan(&scan_pt));
      }
    }

    /* We are part of a PAN-BE network, start slotted CSMA operation */
    slot_operation_start();

    /* Yield our main process. Slot operation will re-schedule itself
     * as long as we are associated */
    PROCESS_YIELD_UNTIL(!be_is_associated);

    /* Will need to re-synchronize */
    be_reset();
  }
  PROCESS_END();
}

/*
 * Unslotted CSMA functions
 */
/*---------------------------------------------------------------------------*/


static struct neighbor_queue *
neighbor_queue_from_addr(const linkaddr_t *addr)
{
	struct neighbor_queue *n = list_head(neighbor_list);
	while(n != NULL) {
		if(linkaddr_cmp(&n->addr, addr)) {
			return n;
		}
		n = list_item_next(n);
	}
	return NULL;
}
/*---------------------------------------------------------------------------*/

static int
neighbor_queue_elements_from_addr(const linkaddr_t *addr)
{
  struct neighbor_queue *n = list_head(neighbor_list);
  while(n != NULL) {
    if(linkaddr_cmp(&n->addr, addr)) {
      return list_length( n->queued_packet_list );
    }
    n = list_item_next(n);
  }
  return -1;
}
#if 0
/*---------------------------------------------------------------------------*/
static clock_time_t
backoff_period(void)
{
	clock_time_t time;
	/* The retransmission time must be proportional to the channel
     check interval of the underlying radio duty cycling layer. */
	time = NETSTACK_RDC.channel_check_interval();

	/* If the radio duty cycle has no channel check interval, we use
	 * the default in IEEE 802.15.4: aUnitBackoffPeriod which is
	 * 20 symbols i.e. 320 usec. That is, 1/3125 second. */
	if(time == 0) {
		time = MAX(CLOCK_SECOND / 3125, 1);
	}
	return time;
}
/*---------------------------------------------------------------------------*/
static void
transmit_packet_list(void *ptr)
{
	struct neighbor_queue *n = ptr;
	if(n) {
		struct rdc_buf_list *q = list_head(n->queued_packet_list);
		if(q != NULL) {
			PRINTF("csma: preparing number %d %p, queue len %d\n", n->transmissions, q,
					list_length(n->queued_packet_list));
			/* Send packets in the neighbor's list */
			NETSTACK_RDC.send_list(packet_sent, n, q);
		}
	}
}
/*---------------------------------------------------------------------------*/
static void
schedule_transmission(struct neighbor_queue *n)
{
	clock_time_t delay;
	int backoff_exponent; /* BE in IEEE 802.15.4 */

	backoff_exponent = MIN(n->collisions, CSMA_MAX_BE);

	/* Compute max delay as per IEEE 802.15.4: 2^BE-1 backoff periods  */
	delay = ((1 << backoff_exponent) - 1) * backoff_period();
	if(delay > 0) {
		/* Pick a time for next transmission */
		delay = random_rand() % delay;
	}

	PRINTF("csma: scheduling transmission in %u ticks, NB=%u, BE=%u\n",
			(unsigned)delay, n->collisions, backoff_exponent);
	ctimer_set(&n->transmit_timer, delay, transmit_packet_list, n);
}
/*---------------------------------------------------------------------------*/
static void
free_packet(struct neighbor_queue *n, struct rdc_buf_list *p, int status)
{
	if(p != NULL) {
		/* Remove packet from list and deallocate */
		list_remove(n->queued_packet_list, p);

		queuebuf_free(p->buf);
		memb_free(&metadata_memb, p->ptr);
		memb_free(&packet_memb, p);
		PRINTF("csma: free_queued_packet, queue length %d, free packets %d\n",
				list_length(n->queued_packet_list), memb_numfree(&packet_memb));
		if(list_head(n->queued_packet_list) != NULL) {
			/* There is a next packet. We reset current tx information */
			n->transmissions = 0;
			n->collisions = CSMA_MIN_BE;
			/* Schedule next transmissions */
			schedule_transmission(n);
		} else {
			/* This was the last packet in the queue, we free the neighbor */
			ctimer_stop(&n->transmit_timer);
			list_remove(neighbor_list, n);
			memb_free(&neighbor_memb, n);
		}
	}
}
/*---------------------------------------------------------------------------*/
static void
tx_done(int status, struct rdc_buf_list *q, struct neighbor_queue *n)
{
	mac_callback_t sent;
	struct qbuf_metadata *metadata;
	void *cptr;
	uint8_t ntx;

	metadata = (struct qbuf_metadata *)q->ptr;
	sent = metadata->sent;
	cptr = metadata->cptr;
	ntx = n->transmissions;

	switch(status) {
	case MAC_TX_OK:
		PRINTF("csma: rexmit ok %d\n", n->transmissions);
		break;
	case MAC_TX_COLLISION:
	case MAC_TX_NOACK:
		PRINTF("csma: drop with status %d after %d transmissions, %d collisions\n",
				status, n->transmissions, n->collisions);
		break;
	default:
		PRINTF("csma: rexmit failed %d: %d\n", n->transmissions, status);
		break;
	}

	free_packet(n, q, status);
	mac_call_sent_callback(sent, cptr, status, ntx);
}
/*---------------------------------------------------------------------------*/
static void
rexmit(struct rdc_buf_list *q, struct neighbor_queue *n)
{
	schedule_transmission(n);
	/* This is needed to correctly attribute energy that we spent
     transmitting this packet. */
	queuebuf_update_attr_from_packetbuf(q->buf);
}
/*---------------------------------------------------------------------------*/
static void
collision(struct rdc_buf_list *q, struct neighbor_queue *n,
		int num_transmissions)
{
	struct qbuf_metadata *metadata;

	metadata = (struct qbuf_metadata *)q->ptr;

	n->collisions += num_transmissions;

	if(n->collisions > CSMA_MAX_BACKOFF) {
		n->collisions = CSMA_MIN_BE;
		/* Increment to indicate a next retry */
		n->transmissions++;
	}

	if(n->transmissions >= metadata->max_transmissions) {
		tx_done(MAC_TX_COLLISION, q, n);
	} else {
		PRINTF("csma: rexmit collision %d\n", n->transmissions);
		rexmit(q, n);
	}
}
/*---------------------------------------------------------------------------*/
static void
noack(struct rdc_buf_list *q, struct neighbor_queue *n, int num_transmissions)
{
	struct qbuf_metadata *metadata;

	metadata = (struct qbuf_metadata *)q->ptr;

	n->collisions = CSMA_MIN_BE;
	n->transmissions += num_transmissions;

	if(n->transmissions >= metadata->max_transmissions) {
		tx_done(MAC_TX_NOACK, q, n);
	} else {
		PRINTF("csma: rexmit noack %d\n", n->transmissions);
		rexmit(q, n);
	}
}
/*---------------------------------------------------------------------------*/
static void
tx_ok(struct rdc_buf_list *q, struct neighbor_queue *n, int num_transmissions)
{
	n->collisions = CSMA_MIN_BE;
	n->transmissions += num_transmissions;
	tx_done(MAC_TX_OK, q, n);
}
/*---------------------------------------------------------------------------*/
static void
packet_sent(void *ptr, int status, int num_transmissions)
{
	struct neighbor_queue *n;
	struct rdc_buf_list *q;

	n = ptr;
	if(n == NULL) {
		return;
	}

	/* Find out what packet this callback refers to */
	for(q = list_head(n->queued_packet_list);
			q != NULL; q = list_item_next(q)) {
		if(queuebuf_attr(q->buf, PACKETBUF_ATTR_MAC_SEQNO) ==
				packetbuf_attr(PACKETBUF_ATTR_MAC_SEQNO)) {
			break;
		}
	}

	if(q == NULL) {
		PRINTF("csma: seqno %d not found\n",
				packetbuf_attr(PACKETBUF_ATTR_MAC_SEQNO));
		return;
	} else if(q->ptr == NULL) {
		PRINTF("csma: no metadata\n");
		return;
	}

	switch(status) {
	case MAC_TX_OK:
		tx_ok(q, n, num_transmissions);
		break;
	case MAC_TX_NOACK:
		noack(q, n, num_transmissions);
		break;
	case MAC_TX_COLLISION:
		collision(q, n, num_transmissions);
		break;
	case MAC_TX_DEFERRED:
		break;
	default:
		tx_done(status, q, n);
		break;
	}
}
#endif /*  */
/*---------------------------------------------------------------------------*/
static void
send_queue_add_packet( const linkaddr_t *addr, mac_callback_t sent, void *ptr )
{
	struct rdc_buf_list *q;
	struct neighbor_queue *n;
	static uint8_t initialized = 0;
	static uint16_t seqno;
#if 0
	const linkaddr_t *addr = packetbuf_addr(PACKETBUF_ADDR_RECEIVER);
#endif
	/*Do not add a new beacon frame if there is already one waiting */
	if( (linkaddr_cmp(addr, &beacon_address) == TRUE) &&
		(neighbor_queue_elements_from_addr >= 1)){
		return;
	}

	if(!initialized) {
		initialized = 1;
		/* Initialize the sequence number to a random value as per 802.15.4. */
		seqno = random_rand();
	}

	if(seqno == 0) {
		/* PACKETBUF_ATTR_MAC_SEQNO cannot be zero, due to a pecuilarity
	   in framer-802154.c. */
		seqno++;
	}
	packetbuf_set_attr(PACKETBUF_ATTR_MAC_SEQNO, seqno++);

	/* Look for the neighbor entry */
	n = neighbor_queue_from_addr(addr);
	if(n == NULL) {
		/* Allocate a new neighbor entry */
		n = memb_alloc(&neighbor_memb);
		if(n != NULL) {
			/* Init neighbor entry */
			linkaddr_copy(&n->addr, addr);
			n->transmissions = 0;
			n->collisions = CSMA_MIN_BE;
			/* Init packet list for this neighbor */
			LIST_STRUCT_INIT(n, queued_packet_list);
			/* Add neighbor to the list */
			list_add(neighbor_list, n);
		}
	}

	if(n != NULL) {
		/* Add packet to the neighbor's queue */
		if(list_length(n->queued_packet_list) < CSMA_MAX_PACKET_PER_NEIGHBOR) {
			q = memb_alloc(&packet_memb);
			if(q != NULL) {
				q->ptr = memb_alloc(&metadata_memb);
				if(q->ptr != NULL) {
					q->buf = queuebuf_new_from_packetbuf();
					if(q->buf != NULL) {
						struct qbuf_metadata *metadata = (struct qbuf_metadata *)q->ptr;
						/* Neighbor and packet successfully allocated */
						if(packetbuf_attr(PACKETBUF_ATTR_MAX_MAC_TRANSMISSIONS) == 0) {
							/* Use default configuration for max transmissions */
							metadata->max_transmissions = CSMA_MAX_MAX_FRAME_RETRIES + 1;
						} else {
							metadata->max_transmissions =
									packetbuf_attr(PACKETBUF_ATTR_MAX_MAC_TRANSMISSIONS);
						}
						metadata->sent = sent;
						metadata->cptr = ptr;
#if PACKETBUF_WITH_PACKET_TYPE
						if(packetbuf_attr(PACKETBUF_ATTR_PACKET_TYPE) ==
								PACKETBUF_ATTR_PACKET_TYPE_ACK) {
							list_push(n->queued_packet_list, q);
						} else
#endif
{
							list_add(n->queued_packet_list, q);
}

						PRINTF("csma: send_packet, queue length %d, free packets %d\n",
								list_length(n->queued_packet_list), memb_numfree(&packet_memb));
						/*NEVER schedule transmission from here*/
#if 0
						/* If q is the first packet in the neighbor's queue, send asap */
						if(list_head(n->queued_packet_list) == q) {
							schedule_transmission(n);
						}
#endif
						return;
					}
					memb_free(&metadata_memb, q->ptr);
					PRINTF("csma: could not allocate queuebuf, dropping packet\n");
				}
				memb_free(&packet_memb, q);
				PRINTF("csma: could not allocate queuebuf, dropping packet\n");
			}
			/* The packet allocation failed. Remove and free neighbor entry if empty. */
			if(list_length(n->queued_packet_list) == 0) {
				list_remove(neighbor_list, n);
				memb_free(&neighbor_memb, n);
			}
		} else {
			PRINTF("csma: Neighbor queue full\n");
		}
		PRINTF("csma: could not allocate packet, dropping packet\n");
	} else {
		PRINTF("csma: could not allocate neighbor, dropping packet\n");
	}
	mac_call_sent_callback(sent, ptr, MAC_TX_ERR, 1);
}

static void
send_packet(mac_callback_t sent, void *ptr)
{
#if 0
	struct rdc_buf_list *q;
	struct neighbor_queue *n;
	static uint8_t initialized = 0;
	static uint16_t seqno;
	const linkaddr_t *addr = packetbuf_addr(PACKETBUF_ADDR_RECEIVER);

	if(!initialized) {
		initialized = 1;
		/* Initialize the sequence number to a random value as per 802.15.4. */
		seqno = random_rand();
	}

	if(seqno == 0) {
		/* PACKETBUF_ATTR_MAC_SEQNO cannot be zero, due to a pecuilarity
       in framer-802154.c. */
		seqno++;
	}
	packetbuf_set_attr(PACKETBUF_ATTR_MAC_SEQNO, seqno++);

	/* Look for the neighbor entry */
	n = neighbor_queue_from_addr(addr);
	if(n == NULL) {
		/* Allocate a new neighbor entry */
		n = memb_alloc(&neighbor_memb);
		if(n != NULL) {
			/* Init neighbor entry */
			linkaddr_copy(&n->addr, addr);
			n->transmissions = 0;
			n->collisions = CSMA_MIN_BE;
			/* Init packet list for this neighbor */
			LIST_STRUCT_INIT(n, queued_packet_list);
			/* Add neighbor to the list */
			list_add(neighbor_list, n);
		}
	}

	if(n != NULL) {
		/* Add packet to the neighbor's queue */
		if(list_length(n->queued_packet_list) < CSMA_MAX_PACKET_PER_NEIGHBOR) {
			q = memb_alloc(&packet_memb);
			if(q != NULL) {
				q->ptr = memb_alloc(&metadata_memb);
				if(q->ptr != NULL) {
					q->buf = queuebuf_new_from_packetbuf();
					if(q->buf != NULL) {
						struct qbuf_metadata *metadata = (struct qbuf_metadata *)q->ptr;
						/* Neighbor and packet successfully allocated */
						if(packetbuf_attr(PACKETBUF_ATTR_MAX_MAC_TRANSMISSIONS) == 0) {
							/* Use default configuration for max transmissions */
							metadata->max_transmissions = CSMA_MAX_MAX_FRAME_RETRIES + 1;
						} else {
							metadata->max_transmissions =
									packetbuf_attr(PACKETBUF_ATTR_MAX_MAC_TRANSMISSIONS);
						}
						metadata->sent = sent;
						metadata->cptr = ptr;
#if PACKETBUF_WITH_PACKET_TYPE
						if(packetbuf_attr(PACKETBUF_ATTR_PACKET_TYPE) ==
								PACKETBUF_ATTR_PACKET_TYPE_ACK) {
							list_push(n->queued_packet_list, q);
						} else
#endif
{
							list_add(n->queued_packet_list, q);
}

						PRINTF("csma: send_packet, queue length %d, free packets %d\n",
								list_length(n->queued_packet_list), memb_numfree(&packet_memb));
						/* If q is the first packet in the neighbor's queue, send asap */
						if(list_head(n->queued_packet_list) == q) {
							schedule_transmission(n);
						}
						return;
					}
					memb_free(&metadata_memb, q->ptr);
					PRINTF("csma: could not allocate queuebuf, dropping packet\n");
				}
				memb_free(&packet_memb, q);
				PRINTF("csma: could not allocate queuebuf, dropping packet\n");
			}
			/* The packet allocation failed. Remove and free neighbor entry if empty. */
			if(list_length(n->queued_packet_list) == 0) {
				list_remove(neighbor_list, n);
				memb_free(&neighbor_memb, n);
			}
		} else {
			PRINTF("csma: Neighbor queue full\n");
		}
		PRINTF("csma: could not allocate packet, dropping packet\n");
	} else {
		PRINTF("csma: could not allocate neighbor, dropping packet\n");
	}
	mac_call_sent_callback(sent, ptr, MAC_TX_ERR, 1);
#endif
}
/*---------------------------------------------------------------------------*/
static void
input_packet(void)
{
/*
 * TODO: input callback disabled for now, need to figure out how to handle
 *      it for beacon frame input
 */
#if 0
	NETSTACK_LLSEC.input();
#endif

}
/*---------------------------------------------------------------------------*/
static int
on(void)
{

  if( be_is_started == FALSE) {
	be_is_started = 1;
	/* Process tx/rx callback  whenever polled */
	//process_start(&be_pending_events_process, NULL);
	/* Send Beacon frames if it is the coordinator */
	//process_start(&beacon_process, NULL);

	/* Prepare the EB packet and schedule it to be sent */
	int beacon_len;

	packetbuf_clear();
	packetbuf_set_attr(PACKETBUF_ATTR_FRAME_TYPE, FRAME802154_BEACONFRAME);

	beacon_len = beacon_packet_create( (uint8_t *)packetbuf_dataptr(), (int)PACKETBUF_SIZE );

	if( beacon_len > 0 ){
		PRINTF("Beacon frame create succeded!\n");

		packetbuf_set_datalen(beacon_len);

		/*Just put beacon frame on send beacon frame queue, it will be processed during slotted CSMA operation*/
		beacon_frame_init();
		beacon_frame.len = packetbuf_copyto(beacon_frame.data);
		packetbuf_attr_copyto(beacon_frame.attrs, beacon_frame.addrs);

		/* try to associate to a network or start one if setup as coordinator */
		process_start(&keep_tsn_process, NULL);
	}
	return 1;
  }
  return 0;
#if 0
  return NETSTACK_RDC.on();
#endif

}
/*---------------------------------------------------------------------------*/
static int
off(int keep_radio_on)
{
	return NETSTACK_RDC.off(keep_radio_on);
}
/*---------------------------------------------------------------------------*/
static unsigned short
channel_check_interval(void)
{
	if(NETSTACK_RDC.channel_check_interval) {
		return NETSTACK_RDC.channel_check_interval();
	}
	return 0;
}
/*---------------------------------------------------------------------------*/
static void
init(void)
{
	PRINTF("SCSMA init\n");
	memb_init(&packet_memb);
	memb_init(&metadata_memb);
	memb_init(&neighbor_memb);
	beacon_frame_init();
	reset_tsn();
	be_reset();
	on();

}
/*---------------------------------------------------------------------------*/
const struct mac_driver csma_driver = {
		"SCSMA",
		init,
		send_packet,
		input_packet,
		on,
		off,
		channel_check_interval,
};
/*---------------------------------------------------------------------------*/
