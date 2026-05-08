/*
 * DUMB RSU mote (Contiki-NG, Sky/MSPSim)
 *
 * Responsibilities:
 *  - Receive QUERY/DATA/EMERGENCY from Mobile ("Mbl").
 *  - Always reply with ACK (unicast) to the sender.
 *  - Re-broadcast EMERGENCY exactly once (fanout=1).
 *  - Keep a small registry of active emergencies (by OriginID).
 *  - Include a compact emergency hint into every outgoing ACK so that
 *    mobiles that appear later can learn about the last received EF.
 *
 * Notes:
 *  - serial_line is bound to UART1 in Cooja (Serial port window).
 *  - RSU does not create emergencies; it only forwards and reports.
 */

#include "contiki.h"
#include "net/ipv6/simple-udp.h"
#include "os/sys/ctimer.h"
#include "dev/serial-line.h"
#include "dev/uart1.h"     /* serial_line on UART1 (Cooja Serial port) */
#include "random.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "dumb_common.h"
#include "dumb_protocol.h"

/* ---------- Metric logging control ---------- */
#ifndef DUMB_METRIC_LOG_ENABLED
#define DUMB_METRIC_LOG_ENABLED 1
#endif

/* ---------- Diagnostic prints control ---------- */
#ifndef DUMB_DIAG
#define DUMB_DIAG 0
#endif


static struct simple_udp_connection udp;
static uint32_t origin_id;                 /* RSU OriginID */
static uint16_t seq16 = 0;                 /* RSU MsgID sequence */
static dumb_dedup_t dedup;                 /* Dedup ring */

/* ------------------------------------------------------------------
 * Emergency registry (RSU)
 * What: Track active EF events by OriginID.
 * Methods: Fixed-size table; linear scan; no dynamic memory.
 */
#define EF_TAB_MAX 8

typedef struct {
    uint8_t  in_use;
    uint32_t origin;
    uint8_t  code;
    uint32_t tick;
} ef_entry_t;

static ef_entry_t ef_tab[EF_TAB_MAX];
static uint32_t ef_tick = 0;

/* Last received EF (for ACK propagation).
 * NOTE: 0 means no emergency.
 * NOTE: FINISH (255) is NOT propagated in ACKs.
 * TODO: Replace selection with priority-based pick when needed
 *       (lower code = higher priority; 1 highest, 244 lowest).
 */
static uint8_t last_rx_ef_code = 0;
static uint32_t last_rx_ef_origin = 0;

static int8_t
ef_find(uint32_t origin)
{
    for(uint8_t i = 0; i < EF_TAB_MAX; ++i) {
        if(ef_tab[i].in_use && ef_tab[i].origin == origin) return (int8_t)i;
    }
    return -1;
}

static void
ef_add_or_update(uint32_t origin, uint8_t code)
{
    if(code == DUMB_EF_NONE || code == DUMB_EF_FINISH) return;

    int8_t idx = ef_find(origin);
    if(idx >= 0) {
        ef_tab[idx].code = code;
        ef_tab[idx].tick = ++ef_tick;
        return;
    }

    int8_t free_i = -1;
    uint32_t min_tick = 0xFFFFFFFFu;
    int8_t oldest_i = 0;

    for(uint8_t i = 0; i < EF_TAB_MAX; ++i) {
        if(!ef_tab[i].in_use && free_i < 0) free_i = (int8_t)i;
        if(ef_tab[i].in_use && ef_tab[i].tick < min_tick) {
            min_tick = ef_tab[i].tick;
            oldest_i = (int8_t)i;
        }
    }

    int8_t put = (free_i >= 0) ? free_i : oldest_i;
    ef_tab[put].in_use = 1;
    ef_tab[put].origin = origin;
    ef_tab[put].code = code;
    ef_tab[put].tick = ++ef_tick;
}

static void
ef_remove(uint32_t origin)
{
    int8_t idx = ef_find(origin);
    if(idx >= 0) ef_tab[idx].in_use = 0;
}

static uint8_t
ef_pick_for_ack(uint32_t *out_origin, uint8_t *out_code)
{
    /* Placeholder: currently "last received" non-finish EF.
     * Future: implement priority-based selection.
     */
    if(last_rx_ef_code == 0 || last_rx_ef_origin == 0) return 0;
    if(out_origin) *out_origin = last_rx_ef_origin;
    if(out_code) *out_code = last_rx_ef_code;
    return 1;
}

/* ------------------------------------------------------------------
 * Fan-out helper (re-broadcast)
 * What: Re-broadcast a frame fanout times with small jitter.
 * Methods: simple_udp_sendto() + ctimer.
 */
typedef struct {
    uint8_t  buf[DUMB_MAX_FRAME];
    uint16_t len;
    uint8_t  remaining;
    struct simple_udp_connection *udp;
    struct ctimer timer;
    uip_ipaddr_t maddr;
} rsu_fanout_ctx_t;

static rsu_fanout_ctx_t rsu_ef_ctx;

static void
rsu_fanout_cb(void *ptr)
{
    rsu_fanout_ctx_t *ctx = (rsu_fanout_ctx_t *)ptr;

    if(ctx == NULL || ctx->remaining == 0) return;

    simple_udp_sendto(ctx->udp, ctx->buf, ctx->len, &ctx->maddr);
    ctx->remaining--;

    if(ctx->remaining) {
        uint16_t d = dumb_rand_jitter_ms();
        ctimer_set(&ctx->timer,
                   (clock_time_t)(d * CLOCK_SECOND / 1000),
                   rsu_fanout_cb, ctx);
    }
}

static void
rsu_start_fanout(rsu_fanout_ctx_t *ctx,
                const uint8_t *frame, uint16_t len,
                uint8_t fanout)
{
    if(ctx == NULL || frame == NULL || len == 0) return;

    uip_create_linklocal_allnodes_mcast(&ctx->maddr);
    ctx->udp = &udp;

    if(len > sizeof(ctx->buf)) len = sizeof(ctx->buf);
    ctx->len = len;
    memcpy(ctx->buf, frame, len);

    /* First send immediately */
    simple_udp_sendto(ctx->udp, ctx->buf, ctx->len, &ctx->maddr);

    if(fanout <= 1) {
        ctx->remaining = 0;
        return;
    }

    ctx->remaining = (uint8_t)(fanout - 1);

    uint16_t d = dumb_rand_jitter_ms();
    ctimer_set(&ctx->timer,
               (clock_time_t)(d * CLOCK_SECOND / 1000),
               rsu_fanout_cb, ctx);
}

/* ------------------------------------------------------------------
 * Helper: send_ack_to()
 * What:
 *  - Build DUMB/ACK from RSU and send unicast back.
 *  - Payload layout (backward compatible extension):
 *    [0]     acked_type
 *    [1..4]  acked_origin (BE)
 *    [5..8]  acked_msg    (BE)
 *    [9]     ef_code (0 if none; FINISH never sent)
 *    [10..13] ef_origin (BE, 0 if none)
 */
static void
send_ack_to(const uip_ipaddr_t *dst,
            uint32_t target_id,
            uint32_t ts_ms,
            uint8_t acked_type,
            uint32_t acked_origin,
            uint32_t acked_msg)
{
    if(dst == NULL) return;

    dumb_fields_t f;
    memset(&f, 0, sizeof(f));

    f.marker[0] = 'R'; f.marker[1] = 'S'; f.marker[2] = 'U';
    f.sender_id = origin_id;
    f.origin_id = origin_id;
    f.msg_type  = DUMB_MSG_ACK;
    f.msg_id    = dumb_make_msgid(&seq16);
    f.target_id = target_id;

    uint8_t pl[14];
    pl[0] = acked_type;
    dumb_u32_be_write(&pl[1], acked_origin);
    dumb_u32_be_write(&pl[5], acked_msg);

    uint32_t ef_origin = 0;
    uint8_t ef_code = 0;
    if(!ef_pick_for_ack(&ef_origin, &ef_code)) {
        ef_origin = 0;
        ef_code = 0;
    }
    pl[9] = ef_code;
    dumb_u32_be_write(&pl[10], ef_origin);

    f.payload = pl;
    f.payload_len = sizeof(pl);
    f.ts_ms = ts_ms;

    uint8_t buf[DUMB_MAX_FRAME];
    uint16_t out_len = 0;
    if(!dumb_pack(&f, buf, sizeof(buf), &out_len)) return;

    simple_udp_sendto(&udp, buf, out_len, dst);
}

/* ------------------------------------------------------------------
 * UDP RX callback
 * What: Parse DUMB frames, dedup, ACK, log, update EF registry,
 *       and re-broadcast emergencies.
 */
static void
udp_rx_cb(struct simple_udp_connection *c,
          const uip_ipaddr_t *sender_addr,
          uint16_t sender_port,
          const uip_ipaddr_t *receiver_addr,
          uint16_t receiver_port,
          const uint8_t *data, uint16_t datalen)
{
    (void)c;
    (void)sender_port;
    (void)receiver_addr;
    (void)receiver_port;

    dumb_fields_t h;
    const uint8_t *pl = NULL;
    uint16_t pl_len = 0;

    /* Drop anything that is not a valid DUMB frame. */
    if(!dumb_parse(data, datalen, &h, &pl, &pl_len)) {
        return;
    }

    /* Accept only frames created by Mobiles ("Mbl"). */
    if(h.marker[0] != 'M' || h.marker[1] != 'b' || h.marker[2] != 'l') {
        return;
    }

    /* ACK QUERY/DATA/EMERGENCY (unicast back to the sender). */
    if(h.msg_type == DUMB_MSG_QUERY ||
       h.msg_type == DUMB_MSG_DATA ||
       h.msg_type == DUMB_MSG_EMERGENCY) {
        send_ack_to(sender_addr, h.origin_id, h.ts_ms,
                    h.msg_type, h.origin_id, h.msg_id);
    }

    /* Dedup (OriginID, MsgID) - process each unique frame once. */
    if(dumb_dedup_has(&dedup, h.origin_id, h.msg_id)) {
        return;
    }
    dumb_dedup_put(&dedup, h.origin_id, h.msg_id);

    /* Optional metric logging in Mobile-like format. */
#if DUMB_METRIC_LOG_ENABLED
    if((h.msg_type == DUMB_MSG_DATA) || (h.msg_type == DUMB_MSG_EMERGENCY)) {
        const dumb_data_payload_t *dpl =
            (const dumb_data_payload_t *)pl;
        uint32_t rx_time = (clock_time()*1000)/CLOCK_SECOND;

	printf("RSU RX origin=%lu msg=%lu hop=%u len=%u time=%lu\n",
	       (unsigned long)h.origin_id,
	       (unsigned long)h.msg_id,
	       (unsigned)(DUMB_DATA_TTL_DEFAULT - dpl->ttl8 + 1),
	       (unsigned)pl_len,
	       (unsigned long)rx_time);
        }

#endif // DUMB_METRIC_LOG_ENABLED

    /* DATA needs no extra RSU-side logic beyond ACK + optional log. */
    if(h.msg_type == DUMB_MSG_DATA) {
        return;
    }

    /* EMERGENCY decoding + registry update + re-broadcast. */
    if(h.msg_type == DUMB_MSG_EMERGENCY) {
        int32_t code = -1;

        if(pl != NULL && pl_len >= 5) {
            /* Expect EFBR signature. */
            if(pl[0] == 'E' && pl[1] == 'F' && pl[2] == 'B' && pl[3] == 'R') {
                code = (int32_t)pl[4];

                /* Update registry. */
                if(code == DUMB_EF_FINISH) {
                    ef_remove(h.origin_id);
                } else if(code != DUMB_EF_NONE) {
                    ef_add_or_update(h.origin_id, (uint8_t)code);
                }

                /* Update last-received placeholder for ACK propagation. */
                if(code == DUMB_EF_FINISH || code == DUMB_EF_NONE) {
                    last_rx_ef_code = 0;
                    last_rx_ef_origin = 0;
                } else {
                    last_rx_ef_code = (uint8_t)code;
                    last_rx_ef_origin = h.origin_id;
                }
            }
        }

        /* Re-broadcast EMERGENCY once (fanout=1). */
        rsu_start_fanout(&rsu_ef_ctx, data, datalen, 1);
        return;
    }
}


PROCESS(rsu_process, "DUMB RSU");
AUTOSTART_PROCESSES(&rsu_process);

PROCESS_THREAD(rsu_process, ev, data)
{
    PROCESS_BEGIN();

    simple_udp_register(&udp, DUMB_UDP_PORT, NULL,
                        DUMB_UDP_PORT, udp_rx_cb);

    /* Serial line on UART1 (Cooja Serial port) */
    serial_line_init();
    uart1_set_input(serial_line_input_byte);

    origin_id = (uint32_t)linkaddr_node_addr.u8[7];
    random_init(origin_id);

    dumb_dedup_init(&dedup);

    while(1) {
        PROCESS_YIELD();

        if(ev == serial_line_event_message && data) {
#if DUMB_DIAG
            printf("RSU_UART: %s\n", (const char *)data);
#endif
        }
    }

    PROCESS_END();
}
