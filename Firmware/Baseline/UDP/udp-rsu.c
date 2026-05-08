/* udp-rsu.c */

#include "contiki.h"
#include "net/ipv6/uip.h"
#include "net/ipv6/simple-udp.h"
#include <stdio.h>
#include <string.h>

#define UDP_PORT 1234

typedef struct {
  uint16_t origin;
  uint16_t msg_id;
  uint8_t  hop;
  uint32_t ts;
} udp_msg_t;

static struct simple_udp_connection udp_conn;

PROCESS(udp_rsu_process, "UDP RSU");
AUTOSTART_PROCESSES(&udp_rsu_process);

static void
udp_rx_callback(struct simple_udp_connection *c,
                const uip_ipaddr_t *sender_addr,
                uint16_t sender_port,
                const uip_ipaddr_t *receiver_addr,
                uint16_t receiver_port,
                const uint8_t *data,
                uint16_t datalen)
{
  if(datalen == sizeof(udp_msg_t)) {
    udp_msg_t rx;
    memcpy(&rx, data, sizeof(rx));

  /* time= is RSU's own reception clock in ms.
   * The analyzer computes latency as delivered_time - created_time,
   * where created_time comes from the mobile's CREATE log line.
   * Both use TICKS_TO_MS(clock_time()), and in Cooja all motes
   * share the same simulated clock, so the subtraction is valid. */
    printf("RSU RX origin=%u msg=%u hop=%u len=%u time=%lu\n",
           rx.origin, rx.msg_id, rx.hop,
           (unsigned)sizeof(rx),
           (clock_time()* 1000UL / CLOCK_SECOND));
  }
}

PROCESS_THREAD(udp_rsu_process, ev, data)
{
  PROCESS_BEGIN();

  simple_udp_register(&udp_conn, UDP_PORT,
                      NULL, UDP_PORT,
                      udp_rx_callback);

  PROCESS_END();
}
