/* udp-mobile.c */

#include "contiki.h"
#include "net/ipv6/uip.h"
#include "net/ipv6/simple-udp.h"
#include "sys/etimer.h"
#include "sys/node-id.h"
#include <stdio.h>
#include <string.h>

#define UDP_PORT      1234
#define SEND_INTERVAL ((CLOCK_SECOND * 5) / 2)   /* 2.5 s in ticks */
#define MAX_HOP 10 // maximum hops allowed for this simulation
#define SEEN_MAX 32 // mitigate data storms by ignoring messages seen to often

typedef struct {
  uint16_t origin;
  uint16_t msg_id;
  uint8_t  hop;
  uint32_t ts;
} udp_msg_t;

typedef struct {
  uint16_t origin;
  uint16_t msg_id;
} seen_msg_t;

static seen_msg_t seen_msg[SEEN_MAX];
static uint8_t seen_count = 0;

static struct simple_udp_connection udp_conn;
static uint16_t local_msg_counter = 0;
static uip_ipaddr_t mcast_addr;

static uint8_t
seen_before(uint16_t origin, uint16_t msg_id)
{
  for(uint8_t i = 0; i < seen_count; i++) {
    if(seen_msg[i].origin == origin &&
       seen_msg[i].msg_id == msg_id) {
      return 1;  // already seen
    }
  }
  return 0;
}

static void
mark_seen(uint16_t origin, uint16_t msg_id)
{
  if(seen_count < SEEN_MAX) {
    seen_msg[seen_count].origin = origin;
    seen_msg[seen_count].msg_id = msg_id;
    seen_count++;
  } else {
    // simple overwrite oldest (ring-ish)
    for(uint8_t i = 1; i < SEEN_MAX; i++) {
      seen_msg[i-1] = seen_msg[i];
    }
    seen_msg[SEEN_MAX-1].origin = origin;
    seen_msg[SEEN_MAX-1].msg_id = msg_id;
  }
}

PROCESS(udp_mobile_process, "UDP Mobile Node");
AUTOSTART_PROCESSES(&udp_mobile_process);

static void
udp_rx_callback(struct simple_udp_connection *c,
                const uip_ipaddr_t *sender_addr,
                uint16_t sender_port,
                const uip_ipaddr_t *receiver_addr,
                uint16_t receiver_port,
                const uint8_t *data,
                uint16_t datalen)
{
  if(datalen != sizeof(udp_msg_t)) return;

  udp_msg_t rx;
  memcpy(&rx, data, sizeof(rx));
  /* Ignore transmissions with maximum allowed hops */
  if(rx.hop >= MAX_HOP) return;
  
  /* Check if message was seen before and ignore it if it's been seen too often */
  
  if(seen_before(rx.origin, rx.msg_id)) {
    return;   // drop duplicate
  }
  mark_seen(rx.origin, rx.msg_id);
  
  /* Ignore own transmissions reflected back */
  if(rx.origin == node_id) return;

  /* Log reception */
  printf("MBL RX origin=%u msg=%u hop=%u\n",
         rx.origin, rx.msg_id, rx.hop);

  /* Relay: increment hop and rebroadcast */
  rx.hop += 1;

  printf("MBL RTX origin=%u msg=%u hop=%u len=%u\n",
         rx.origin, rx.msg_id, rx.hop,
         (unsigned)sizeof(rx));

  simple_udp_sendto(&udp_conn, &rx, sizeof(rx), &mcast_addr);
}

PROCESS_THREAD(udp_mobile_process, ev, data)
{
  static struct etimer timer;

  PROCESS_BEGIN();

  simple_udp_register(&udp_conn, UDP_PORT,
                      NULL, UDP_PORT,
                      udp_rx_callback);

  uip_create_linklocal_allnodes_mcast(&mcast_addr);

  etimer_set(&timer, SEND_INTERVAL);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));

    udp_msg_t msg;
    msg.origin = node_id;
    msg.msg_id = local_msg_counter++;
    msg.hop    = 0;
    msg.ts     = (clock_time() * 1000UL / CLOCK_SECOND);

    printf("CREATE origin=%u msg=%u time=%lu\n",
           msg.origin, msg.msg_id,
           (clock_time() * 1000UL / CLOCK_SECOND));

    printf("MBL TX origin=%u msg=%u hop=%u len=%u\n",
           msg.origin, msg.msg_id, msg.hop,
           (unsigned)sizeof(msg));

    simple_udp_sendto(&udp_conn, &msg, sizeof(msg), &mcast_addr);

    etimer_reset(&timer);
  }

  PROCESS_END();
}
