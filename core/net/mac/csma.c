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

/*
 * Used to convert RTIMERTICKS to US, to use RTIMERTICKS_TO_US()
 * for large values is problematic
 */
#define US_IN_ONE_RTIMERTICK ( RTIMERTICKS_TO_US(1) )


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


/* CSMA timing default values */

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


#define IEEE802154_BSD			(15300)
#define NUM_SUPERFRAME_SLOTS	(16)

#define IEEE802154_DEFAULT_BO	(10)
#define IEEE802154_DEFAULT_SO	(7)

/* Calculate 2^(n) using bit shifting */
#define PWR2(n)	(((n) > 0) ? (2<<((n)-1)) : (2))

#define CSMA_DEFAULT_TS_BI	3916800	/*IEEE802154_DEFAULT_BO=8, IEEE802154_DEFAULT_SO=7*/
#define CSMA_DEFAULT_TS_SD  1958400

/* Superframe structure constants */
#define LAST_ACTIVE_TS 		(15)
#define LAST_INACTIVE_TS	(31)
#define FIRST_INACTIVE_TS	(16)

#define MAX_ACTIVE_TSN		(16) /*Used to schedule CSMA send operation*/


/* TSN value used when we are not in slotted CSMA operation */
#define MAX_TSN_VALUE	(32)
#define TSN_INVALID		(0xFF) /* This node has not been associated */
#define TSN_INACTIVE	(0xFE) /* This node is associated but in the inactive period*/

#define BACKOFF_PERIOD	(1)	   /* Backoff period for slotted CSMA is one timeslot */

/* Calculate packet tx/rx duration in rtimer ticks based on sent
 * packet len in bytes with 802.15.4 250kbps data rate.
 * One byte = 32us. Add two bytes for CRC and one for len field */
#define PACKET_DURATION(len) US_TO_RTIMERTICKS(32 * ((len) + 3))


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
};
/* CSMA timeslot timing (in rtimer ticks) */
static rtimer_clock_t csma_timing[csma_ts_elements_count]={0};

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
	uint8_t  tsn_value;
	uint8_t	is_tsn_start_time_set;
	volatile rtimer_clock_t  tsn_start_time;
}tsn_into_t;

/* Updated by keep_tsn_info process, used in different process */
static tsn_into_t current_tsn = {TSN_INVALID, FALSE, (rtimer_clock_t)0 };

/* IEEE 802.15.4 superframe structure */
static uint8_t	sf_bo = 0;
static uint8_t	sf_so = 0;

static unsigned long int	beacon_interval_us 		= 0;
static unsigned long int	superframe_duration_us 	= 0;
static unsigned long int	active_ts_us 			= 0;
static unsigned long int	inactive_ts_us 			= 0;


#if LINKADDR_SIZE == 8
/* 802.15.4 broadcast MAC address  */
const linkaddr_t broadcast_address = { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } };
/* Address used for the EB virtual neighbor queue */
const linkaddr_t beacon_address = { { 0, 0, 0, 0, 0, 0, 0, 0 } };
#else /* LINKADDR_SIZE == 8 */
const linkaddr_t broadcast_address = { { 0xff, 0xff } };
const linkaddr_t beacon_address = { { 0, 0 } }; /*Virtual address for beacon frames*/
#endif /* LINKADDR_SIZE == 8 */


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



#define MAX_QUEUED_PACKETS QUEUEBUF_NUM
MEMB(neighbor_memb, struct neighbor_queue, CSMA_MAX_NEIGHBOR_QUEUES);
MEMB(packet_memb, struct rdc_buf_list, MAX_QUEUED_PACKETS);
MEMB(metadata_memb, struct qbuf_metadata, MAX_QUEUED_PACKETS);
LIST(neighbor_list);

PROCESS(keep_tsn_process, "PAN-BE: Keep information about time slot number during BE operation");
PROCESS(pending_send_process, "PAN_BE: pending send events process");
static PT_THREAD(tsn_update(struct rtimer *t, void *ptr));
static struct pt tsn_update_pt;
/*
 *	Function prototypes
 */

static int 		prepare_beacon_frame( void );

static uint8_t 	tsn_update_schedule	(struct rtimer *tm,
									 rtimer_clock_t ref_time,
									 rtimer_clock_t offset);

static struct neighbor_queue * next_slot_nq	( const uint8_t tsn );

static uint8_t get_tsn_start_time	(rtimer_clock_t * tns_start_time);
static uint8_t get_tsn_value	 	(uint8_t * tsn);
static void    rsync_tsn			(const uint8_t tsn_ref, const rtimer_clock_t now);
static void    reset_tsn			(void);

uint8_t test_radio_timestamp( void );

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
 * 					 Beacon frame manupulation functions
 ****************************************************************************/

/* Beacon frame init */
void
beacon_frame_init( void )
{
	memset((void*)(&beacon_frame),0,sizeof(struct queuebuf_data));
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
  p.superframe_spec.beaconOrder = IEEE802154_DEFAULT_BO;
  p.superframe_spec.superframeOrder = IEEE802154_DEFAULT_SO;

  p.src_pid = frame802154_get_pan_id();
  p.dest_pid = frame802154_get_pan_id();
  linkaddr_copy((linkaddr_t *)&p.src_addr, &linkaddr_node_addr);
  /*Send broadcast*/
  p.dest_addr[0] = 0xff;
  p.dest_addr[1] = 0xff;

  curr_len = frame802154_create(&p, buf);

  return curr_len;
}

static int
prepare_beacon_frame( void )
{
	int beacon_len = 0;

	packetbuf_clear();
	packetbuf_set_attr(PACKETBUF_ATTR_FRAME_TYPE, FRAME802154_BEACONFRAME);

	beacon_len = beacon_packet_create( (uint8_t *)packetbuf_dataptr(), (int)PACKETBUF_SIZE );

	if( beacon_len > 0 ){
		PRINTF("Beacon frame create succeed!\n");
		packetbuf_set_datalen(beacon_len);

		/*Store beacon frame in a local queue, it will be used later*/
		beacon_frame_init();
		beacon_frame.len = packetbuf_copyto(beacon_frame.data);
		packetbuf_attr_copyto(beacon_frame.attrs, beacon_frame.addrs);
	}

	return beacon_len;
}

uint8_t
get_beacon_frame_bo( frame802154_t *frame )
{
	uint8_t bo;
	if( frame != NULL )
	{
		bo = frame->superframe_spec.beaconOrder;
		if( bo < 15 )
			return bo;
	}

	return 0; /* Not a valid BO*/
}

/*
 *	Note:  get_beacon_frame_bo() should be called first.
 */
uint8_t
get_beacon_frame_so( frame802154_t *frame )
{
	uint8_t so;
	if( (frame != NULL) )
	{
		so = frame->superframe_spec.superframeOrder;
		if( so < sf_bo )	/*Need to validate against defined Beacon order*/
			return so;
	}

	return 0; /* Not a valid BO*/
}

uint8_t
calculate_superframe_timing( uint8_t bo, uint8_t so )
{
	if( so < bo )
	{
		beacon_interval_us 		= (unsigned long int)IEEE802154_BSD * (unsigned long int)PWR2(bo);
		superframe_duration_us 	= (unsigned long int)IEEE802154_BSD * (unsigned long int)PWR2(so);
		active_ts_us 			= superframe_duration_us / NUM_SUPERFRAME_SLOTS;
		inactive_ts_us 			= (beacon_interval_us - superframe_duration_us) / NUM_SUPERFRAME_SLOTS;

		/* Update slotted CSMA timing information */
		csma_timing[csma_ts_active_length] = (rtimer_clock_t)(active_ts_us/US_IN_ONE_RTIMERTICK);
		csma_timing[csma_ts_inactive_length] = (rtimer_clock_t)(inactive_ts_us/US_IN_ONE_RTIMERTICK);

		PRINTF("calculate_superframe_timing()\n");
		PRINTF("bo: %u\n",bo);
		PRINTF("so: %u\n",so);
		PRINTF("Updated csma_timing[csma_ts_active_length]: %u\n",csma_timing[csma_ts_active_length]);
		PRINTF("Updated csma_timing[csma_ts_inactive_length]: %u\n",csma_timing[csma_ts_inactive_length]);
		PRINTF("beacon_interval_us: %lu\n",beacon_interval_us);
		PRINTF("superframe_duration_us: %lu\n",superframe_duration_us);
		PRINTF("active_ts_us: %lu\n",active_ts_us);
		PRINTF("inactive_ts_us: %lu\n",inactive_ts_us);

		return TRUE;
	}

	return FALSE;
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
rsync_tsn( const uint8_t tsn_ref, const rtimer_clock_t now )
{
	current_tsn.tsn_value = tsn_ref;
	current_tsn.tsn_start_time = now;
	current_tsn.is_tsn_start_time_set = TRUE;
	//PRINTF("TSN_sync: %d st: %u\n",current_tsn.tsn_value, current_tsn.tsn_start_time);
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
	//PRINTF("TSN_inc: %d timestamp:%u\n",current_tsn.tsn_value, next_tsn_start_value);
}
/*****************************************************************************
 * 							SCHEDULING FUNCTIONS
 ****************************************************************************/

uint8_t
enable_RX_poll_mode( void )
{
	radio_value_t radio_rx_mode;

	/* Radio Rx mode */
	if(NETSTACK_RADIO.get_value(RADIO_PARAM_RX_MODE, &radio_rx_mode) != RADIO_RESULT_OK) {
		printf("WARN:! radio does not support getting RADIO_PARAM_RX_MODE. Abort init.\n");
		return FALSE;
	}
	/* Disable radio in frame filtering */
	radio_rx_mode &= ~RADIO_RX_MODE_ADDRESS_FILTER;
	/* Unset autoack */
	radio_rx_mode &= ~RADIO_RX_MODE_AUTOACK;
	/* Set radio in poll mode */
	radio_rx_mode |= RADIO_RX_MODE_POLL_MODE;
	if(NETSTACK_RADIO.set_value(RADIO_PARAM_RX_MODE, radio_rx_mode) != RADIO_RESULT_OK) {
		printf("WARN:! radio does not support setting required RADIO_PARAM_RX_MODE. Abort init.\n");
		return FALSE;
	}

	return TRUE;
}

uint8_t
disable_RX_poll_mode( void )
{
	radio_value_t radio_rx_mode;

	/* Radio Rx mode */
	if(NETSTACK_RADIO.get_value(RADIO_PARAM_RX_MODE, &radio_rx_mode) != RADIO_RESULT_OK) {
		printf("WARN:! radio does not support getting RADIO_PARAM_RX_MODE. Abort init.\n");
		return FALSE;
	}
	/* Enable radio in frame filtering */
	radio_rx_mode |= RADIO_RX_MODE_ADDRESS_FILTER;
	/* Set autoack */
	radio_rx_mode |= RADIO_RX_MODE_AUTOACK;
	/* Unset radio in poll mode */
	radio_rx_mode &= ~RADIO_RX_MODE_POLL_MODE;

	if(NETSTACK_RADIO.set_value(RADIO_PARAM_RX_MODE, radio_rx_mode) != RADIO_RESULT_OK) {
		printf("WARN:! radio does not support setting required RADIO_PARAM_RX_MODE. Abort init.\n");
		return FALSE;
	}

	return TRUE;
}

uint8_t
test_radio_timestamp( void )
{
	rtimer_clock_t t;

	/* Test getting timestamp */
	if(NETSTACK_RADIO.get_object(RADIO_PARAM_LAST_PACKET_TIMESTAMP, &t, sizeof(rtimer_clock_t)) != RADIO_RESULT_OK) {
		printf("PAN-BE:! Abort init.(%d)\n", NETSTACK_RADIO.get_object(RADIO_PARAM_LAST_PACKET_TIMESTAMP, &t, sizeof(rtimer_clock_t)));
		return FALSE;
	}

	return TRUE;
}

/* Setup BE as a coordinator */
static void
start_coordinator(void)
{
  frame802154_set_pan_id(IEEE802154_PANID);

  be_is_associated = TRUE;

  PRINTF("BE-PAN: starting as coordinator, PAN ID %x \n",
		  frame802154_get_pan_id());
  /*
   * Re-calculate superframe timing values, just in case macro definitions
   * were manually updated during testing
   */
  calculate_superframe_timing(IEEE802154_DEFAULT_BO, IEEE802154_DEFAULT_SO);

  rsync_tsn(LAST_INACTIVE_TS, RTIMER_NOW());

}
/*---------------------------------------------------------------------------*/


static void packet_sent(void *ptr, int status, int num_transmissions);
static void transmit_packet_list(void *ptr);


/*---------------------------------------------------------------------------*/
static
PT_THREAD(tx_slot(struct pt *pt, struct rtimer *t))
{
  PT_BEGIN(pt);

  if( current_tsn.tsn_value == 0 ) /*Send Beacon*/
  {
	  /* Copy to beacon frame to the radio buffer */
	  if( beacon_frame.len > 0 )
	  {
		  NETSTACK_RADIO.on();
		  if( NETSTACK_RADIO.prepare(beacon_frame.data, beacon_frame.len) == 0 ){ /* 0 means success */
			  //TSN_SCHEDULE_AND_YIELD(pt, t, current_tsn.tsn_start_time, csma_timing[csma_ts_send_beacon_guard]);
			  BUSYWAIT_UNTIL_ABS(0, current_tsn.tsn_start_time, csma_timing[csma_ts_send_beacon_guard]);
			  rsync_tsn(0,RTIMER_NOW());
			  NETSTACK_RADIO.transmit(beacon_frame.len);
		  }
		  else{
			  /*Error handling*/
		  }
	  }
  }
  else if((current_tsn.tsn_value < 16) && (nq != NULL))
  {
	  /* Poll process for send all the packets in the neighbor buffer */
	  process_poll(&pending_send_process);
  }

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
    csma_timing[i] = (rtimer_clock_t)(csma_default_timing_us[i]/US_IN_ONE_RTIMERTICK);
  }

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


#if 0
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

  PT_BEGIN(pt);

  PT_END(pt);
}
#endif

/* Protothread for updating TSN information, called from rtimer interrupt
 * and scheduled from tsn_update_schedule */
static
PT_THREAD(tsn_update(struct rtimer *t, void *ptr))
{
  static uint8_t scheduled = FALSE;
  static uint8_t curr_tsn = TSN_INVALID;
  static uint8_t is_valid_tsn = FALSE;
  static rtimer_clock_t curr_start_time = 0;
  static rtimer_clock_t time_to_next_ts = 0;

  PT_BEGIN(&tsn_update_pt);


  while( be_is_associated )
  {
	  increment_tsn( RTIMER_NOW() );

	  //PRINTF("TSN_inc: %d timestamp:%u\n",current_tsn.tsn_value, RTIMER_NOW());

	  is_valid_tsn = get_tsn_start_time(&curr_start_time) && get_tsn_value(&curr_tsn);

	  if( is_valid_tsn == TRUE )
	  {
		  if( curr_tsn == 0 )  /*Beacon Frame*/
		  {
			  active_period = TRUE;
			  NETSTACK_RADIO.on();
			  if( be_is_coordinator )
			  {
				  /*send_beacon PT spawn*/
				  static struct pt slot_tx_pt;
				  PT_SPAWN(&tsn_update_pt, &slot_tx_pt, tx_slot(&slot_tx_pt, t));
			  }
			  else
			  {
				  /*beacon read PT spawn*/
				  current_tsn.tsn_start_time += csma_timing[csma_ts_send_beacon_guard];
				  BUSYWAIT_UNTIL_ABS(0, current_tsn.tsn_start_time, csma_timing[csma_ts_send_beacon_guard]);
				  //static struct pt beacon_rx_pt;
				  //PT_SPAWN(&tsn_update_pt, &beacon_rx_pt, beacon_rx(&beacon_rx_pt));
			  }
		  }
		  else if( (curr_tsn <= LAST_ACTIVE_TS) )
		  {
			  if(nq != NULL) {
				/* We have something to transmit, do the following:
				 * 1. send
				 * 2. post tx callback
				 **/
				static struct pt slot_tx_pt;
				PT_SPAWN(&tsn_update_pt, &slot_tx_pt, tx_slot(&slot_tx_pt, t));
			  }
		  }


		  if(curr_tsn == LAST_ACTIVE_TS )
		  {
			  prepare_for_inactive = TRUE;
			  disable_RX_poll_mode();
		  }
		  else if( curr_tsn == FIRST_INACTIVE_TS )
		  {
			  active_period = FALSE;
			  NETSTACK_RADIO.off();
		  }
		  else if( curr_tsn == LAST_INACTIVE_TS)
		  {
			  prepare_for_active = TRUE;
			  enable_RX_poll_mode();
		  }

		  if( curr_tsn < 16 )
		  {
			  time_to_next_ts = csma_timing[csma_ts_active_length];
		  }
		  else
		  {
			  time_to_next_ts = csma_timing[csma_ts_inactive_length];
		  }

		  if( (curr_tsn == LAST_INACTIVE_TS) && be_is_coordinator )
		  {
			  time_to_next_ts -= csma_timing[csma_ts_send_beacon_guard];
		  }

		  /*Do we have something to send in the next time slot?*/
		  nq = next_slot_nq( (curr_tsn + 1) % MAX_TSN_VALUE );

		  scheduled = tsn_update_schedule(t, curr_start_time, time_to_next_ts);

		  if(!scheduled){
			  /*TODO Error handling*/
			  PRINTF(" *!!\n");
		  }

	  }
	  PT_YIELD(&tsn_update_pt);
  }

  PT_END(&tsn_update_pt);
}

static uint8_t
tsn_update_schedule(struct rtimer *tm, const rtimer_clock_t ref_time, const rtimer_clock_t offset)
{
	int r;
	rtimer_clock_t now = RTIMER_NOW();
	int missed = check_timer_miss(ref_time, offset - RTIMER_GUARD, now);

	if(missed) {
	  PRINTF(" *!\n");
	  return 0;
	}
	r = rtimer_set(tm, (ref_time + offset), 1, (void (*)(struct rtimer *, void *))tsn_update, NULL);

	if(r != RTIMER_OK) {
		PRINTF(" *!!\n");
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

	/*Prepare for slotted CSMA*/
	disable_RX_poll_mode();

	do{
		if( !get_tsn_value(&curr_tns) || !get_tsn_start_time(&prev_ts_start) ){
			return;	/*Invalid TNS or start time value*/
		}
		time_to_next_ts = csma_timing[csma_ts_active_length];

		PRINTF("prev_ts_start=%u, time_to_next_ts=%u\n", prev_ts_start, time_to_next_ts);

	}while( !tsn_update_schedule(&tsn_update_timer, prev_ts_start, time_to_next_ts) );
}

/*---------------------------------------------------------------------------*/
/* Scanning protothread, called by be_process:
 * Listen until it receives a beacon frame and attempt to associate.
 */
PT_THREAD(beacon_scan(struct pt *pt))
{
  PT_BEGIN(pt);

  static struct etimer scan_timer;
  etimer_set(&scan_timer, 1);
  int is_packet_pending;
  frame802154_t frame;
  rtimer_clock_t t0;

  PRINTF("beacon_scan()\n");

  /* Try to associate */
  while (!be_is_associated && !be_is_coordinator)
  {
		 NETSTACK_RADIO.on();

		is_packet_pending = NETSTACK_RADIO.pending_packet();

	    if(!is_packet_pending && NETSTACK_RADIO.receiving_packet()) {
	      /* If we are currently receiving a packet, wait until end of reception */
	      t0 = RTIMER_NOW();
	      BUSYWAIT_UNTIL_ABS((is_packet_pending = NETSTACK_RADIO.pending_packet()), t0, RTIMER_SECOND / 100);
	    }

		if(is_packet_pending && !be_is_associated)
		{
			rtimer_clock_t rx_start_time;
			/* At the end of the reception, get an more accurate estimate of SFD arrival time */
			NETSTACK_RADIO.get_object(RADIO_PARAM_LAST_PACKET_TIMESTAMP, &rx_start_time, sizeof(rtimer_clock_t));
			rx_start_time += csma_timing[csma_ts_send_beacon_guard]+100;
			rsync_tsn( 0, rx_start_time  );

			current_tsn.tsn_value = 0;
			current_tsn.tsn_start_time = rx_start_time;
			current_tsn.is_tsn_start_time_set = TRUE;
			PRINTF("TSN_sync: %d st: %u\n",current_tsn.tsn_value, current_tsn.tsn_start_time);

			/* Read packet */
			uint8_t* pBuf = (uint8_t *)packetbuf_dataptr();
			int len = NETSTACK_RADIO.read(packetbuf_dataptr(), packetbuf_remaininglen());

			frame802154_parse(pBuf, len, &frame);

			/*Simple association process*/
			if( ( FRAME802154_BEACONFRAME == frame.fcf.frame_type ) &&  	/*It is a beacon frame type */
				( FRAME802154_IEEE802154E_2012 >= frame.fcf.frame_version )  ){ 	/* It is NOT an Enhanced beacon frame*/
				frame802154_set_pan_id( frame.src_pid );

				if( (sf_bo = get_beacon_frame_bo(&frame)) && (sf_so = get_beacon_frame_so(&frame))  )
				{
					if( calculate_superframe_timing(sf_bo, sf_so) )
					{
						be_is_associated = TRUE;
					}
				}

				PRINTF("Node associated to PAN id: <%x> \n", frame.src_pid);
			}
		}
		else if(!be_is_coordinator)
		{
	      /* Go back to scanning */
	      etimer_reset(&scan_timer);
	      PT_WAIT_UNTIL(pt, etimer_expired(&scan_timer));

	    }
	}

  PT_END(pt);
}

/*---------------------------------------------------------------------------*/
/* Reading protothread, called by be_process:
 * Listen until it receives a beacon frame within the active timeslot 0
 */
#if 0
/* Disabled, since it is not working properly */
static
PT_THREAD(beacon_rx(struct pt *pt))
{
	PT_BEGIN(pt);

	static struct etimer scan_timer;
	int is_packet_pending = FALSE;
	etimer_set(&scan_timer, 1);
	frame802154_t frame;

	int try = 0;

	rtimer_clock_t t0;
	rtimer_clock_t offset = 32;

	PRINTF("PT beacon_rx\n");

	NETSTACK_RADIO.on();

	is_packet_pending = NETSTACK_RADIO.pending_packet();

	while( (try++ <= 100) && !is_packet_pending  )
	{
		if( NETSTACK_RADIO.receiving_packet() )
		{
			rsync_tsn(0, RTIMER_NOW());
			/* If we are currently receiving a packet, wait until end of reception */
			BUSYWAIT_UNTIL_ABS((is_packet_pending = NETSTACK_RADIO.pending_packet()), t0, RTIMER_SECOND / 100);
		}
		else
		{
			/* Otherwise wait for 5 rtimer ticks (BLOCKING WAIT), exit when we see a packet in the air */
			t0 = RTIMER_NOW();
			BUSYWAIT_UNTIL_ABS(NETSTACK_RADIO.receiving_packet(), t0, (t0 + offset));
			is_packet_pending = NETSTACK_RADIO.pending_packet();
			if( is_packet_pending )
			{
				/*Rsync TS0 start time considering the time to transmit the beacon frame*/
				t0 = RTIMER_NOW() - PACKET_DURATION(beacon_frame.len);
				rsync_tsn(0, t0);
			}
		}
	}

	if(is_packet_pending)
	{
		/* Read packet */
		uint8_t* pBuf = (uint8_t *)packetbuf_dataptr();
		int len = NETSTACK_RADIO.read(packetbuf_dataptr(), packetbuf_remaininglen());

		frame802154_parse(pBuf, len, &frame);

		if( ( FRAME802154_BEACONFRAME 	   == frame.fcf.frame_type 		) &&  /*It is a beacon frame type */
			( FRAME802154_IEEE802154E_2012 >= frame.fcf.frame_version 	) &&  /* It is NOT an Enhanced beacon frame*/
			( frame802154_get_pan_id() 	   == frame.src_pid				)) 	  /* It is the same PAN that we're associated with*/
		{
			beacon_recv = TRUE;
		}
	}

	if(!beacon_recv)
	{
		/*If we did not received the beacon frame, leave the PAN until we get a beacon again.*/
		be_is_associated = FALSE;
		PRINTF("Leaving PAN!\n");
	}

  PT_END(pt);
}
#endif

/* Process to keep TSN data updated */

/*
 *	Description: This process is taking care of updating the current TSN value and initial time
 *	             (rtimer_clock_t). All this information is stored in a struct tsn_t
 *
 *	             It does nothing until be_is_associated is true.
 *
 *	             active_period   -> 0  <= tsn_value < 16
 *	             inactive_period -> 16 <= tsn_value < 32
 *
 *	Steps:
 *		1. While !be_is_associated, wait one clock_t using etimer.
 *		2. Call start_tsn_update().
 *		3. Yield until (!be_is_associated), it means we need to sync and start again
 *		   because we lost beacon frame tracking.
 *
 */

PROCESS_THREAD(keep_tsn_process, ev, data){

	static struct etimer tsn_timer;

	PROCESS_BEGIN();
	/* Set the timer to send beacons periodically */
	etimer_set(&tsn_timer, (clock_time_t)(1));

	PRINTF("TNS_PROCESS\n");

	while(_ALWAYS_)
	{
		while(!be_is_associated)
		{
			if(be_is_coordinator) /* We are coordinator, start operating now */
			{
				if( prepare_beacon_frame() )
				{
					start_coordinator();
				}
				else /*Failed to create a beacon frame, abort!*/
				{
					break;
				}
			}
			else/* Start scanning, will attempt to join when receiving an EB */
			{
				static struct pt scan_pt;
				enable_RX_poll_mode();
				PROCESS_PT_SPAWN(&scan_pt, beacon_scan(&scan_pt));
			}

			if(!be_is_associated){
				etimer_reset(&tsn_timer);
				PROCESS_WAIT_UNTIL(etimer_expired(&tsn_timer));
			}
		}

		tsn_update_start();

		/* Yield our keep_tsn process. tsn_update will schedule itself as long as
		 * we keep associated */

		 PRINTF("keep_tsn_process YIELD!\n");
		 PROCESS_YIELD_UNTIL(!be_is_associated);

	}

	PROCESS_END();
}

PROCESS_THREAD(pending_send_process, ev, data)
{
  PROCESS_BEGIN();
  while( _ALWAYS_ ) {
    PROCESS_YIELD_UNTIL(ev == PROCESS_EVENT_POLL);

    /*
     * Only RFD can transmit when there is something in
     * the transmit queue
     */
    if( active_period 		&&
    	!be_is_coordinator)
    {
		PRINTF("Sending data! \n");
    	transmit_packet_list(nq);
    }
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

/* Version used when trying to get slotted CSMA to work */
static void
schedule_transmission(struct neighbor_queue *n)
{
	clock_time_t delay;
	int backoff_exponent; /* BE in IEEE 802.15.4 */
	uint8_t scheduled_tsn;

	backoff_exponent = MIN(n->collisions, CSMA_MAX_BE);

	/* Compute max delay as per IEEE 802.15.4: 2^BE-1 backoff periods  */
	delay = ((1 << backoff_exponent) - 1) * BACKOFF_PERIOD;
	if(delay > 0) {
		/* Pick a time for next transmission */
		delay = random_rand() % delay;
	}

	scheduled_tsn = (current_tsn.tsn_value + delay) % MAX_ACTIVE_TSN;

	/* Time slot 0 is reserved to beacon frame*/
	if( scheduled_tsn == 0 ){
		++scheduled_tsn;
	}

	n->transmit_tsn = scheduled_tsn;
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


static void
send_packet(mac_callback_t sent, void *ptr)
{

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

}
/*---------------------------------------------------------------------------*/
static void
input_packet(void)
{
	if( active_period )
	{
		NETSTACK_LLSEC.input();
	}

}
/*---------------------------------------------------------------------------*/
static int
on(void)
{



  if( be_is_started == FALSE) {
	be_is_started = 1;

	/* Process to send all the data packages pending */
	process_start(&pending_send_process, NULL);
	/* try to associate to a network or start one if setup as coordinator */
	process_start(&keep_tsn_process, NULL);

	return NETSTACK_RDC.on();;
  }
  return 0;


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
	PRINTF("rtimer_clock_t : %d bytes", sizeof(rtimer_clock_t));
	memb_init(&packet_memb);
	memb_init(&metadata_memb);
	memb_init(&neighbor_memb);

	if( test_radio_timestamp() == FALSE )
	{
		return;
	}

	if( enable_RX_poll_mode() == FALSE )
	{
		return;
	}


	beacon_frame_init();
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
