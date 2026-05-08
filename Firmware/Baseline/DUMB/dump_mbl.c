/*
 * DUMB Mobile mote (Contiki-NG, Sky/MSPSim)
 *
 * Responsibilities:
 *  - Periodic REQ_LOC over UART1; parse "LOC id x y ts" replies.
 *  - Track position (x_dm, y_dm), timestamp, speed (dm/s), direction.
 *  - Sudden-stop detector: if motion <= STOP_THRESH_DM for >= STOP_MIN_MS,
 *    declare Emergency Braking (EF code 1). On resume, send EF_FINISH (255).
 *  - Include motion metrics in DATA and EF payloads.
 *  - Maintain a local registry of active emergencies (by OriginID).
 *  - Embed last-known EF flag + origin into every outgoing QUERY.
 *  - Parse QUERY from other mobiles to absorb EF state.
 *  - Dedup + compact carry ring. Flush carry to RSU when RSU visible.
 *    Carry stores 21-byte records (not including platform-base padding) 
 *    and not full wire frames. The DUMB frame
 *    is rebuilt from the record at flush time using dumb_pack().
 *  - Friend-by-ACK: maintain two long-lived friend slots.
 *    * Friends are included in every originated DATA.
 *    * Retransmit each originated DATA DUMB_FRIEND_RETRIES times total
 *      (1 initial send + retries), driven by t_data_ack_window ctimer.
 *    * Frame is REBUILT for each retry so the current friend list is
 *      always included; msg_id and ts_ms are frozen at creation time.
 *    * Friend slots are updated only at the end of each ACK window.
 *    * A friend is removed only after FRIEND_MISS_LIMIT consecutive
 *      per-message misses (not immediately on a single miss).
 *  - Metrics (x,y,v,dir,rssi) belong to the original creator and must
 *    be forwarded unchanged; only sender_id and ttl8 change per hop.
 */

#include "contiki.h"
#include "net/ipv6/simple-udp.h"
#include "os/sys/etimer.h"
#include "os/sys/ctimer.h"
#include "dev/serial-line.h"
#include "dev/uart1.h"
#include "dev/leds.h"
#include "random.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "dumb_common.h"
#include "dumb_protocol.h"

/* ------------------------------------------------------------------ */
/*  Build-time feature flags                                           */
/* ------------------------------------------------------------------ */
#ifndef DUMB_DIAG
#define DUMB_DIAG 0
#endif

#ifndef FRIEND_LIST_MONITOR_ENABLED
#define FRIEND_LIST_MONITOR_ENABLED 0
#endif

#ifndef LOC_PRINT
#define LOC_PRINT 0
#endif

#ifndef DUMB_METRIC_LOG_ENABLED
#define DUMB_METRIC_LOG_ENABLED 1
#endif

/*
 * FRIEND_MISS_LIMIT: consecutive per-message miss cycles before a
 * friend slot is cleared. One "miss" = one full originated DATA
 * message cycle (all DUMB_FRIEND_RETRIES sends) during which the
 * friend sent no ACK at all.
 */
#ifndef FRIEND_MISS_LIMIT
#define FRIEND_MISS_LIMIT 3
#endif

/* ------------------------------------------------------------------ */
/*  UDP connection                                                     */
/* ------------------------------------------------------------------ */
static struct simple_udp_connection udp;

/* ------------------------------------------------------------------ */
/*  Forward declarations                                               */
/* ------------------------------------------------------------------ */
static void send_ack_unicast(const uip_ipaddr_t *dst,
                             uint32_t target_id,
                             uint32_t ts_ms,
                             uint8_t  acked_type,
                             uint32_t acked_origin,
                             uint32_t acked_msg);

static void send_ack_mcast(uint32_t target_id,
                             uint32_t ts_ms,
                             uint8_t acked_type,
                             uint32_t acked_origin,
                             uint32_t acked_msg);

static void start_carry_flush(void);

/* ------------------------------------------------------------------ */
/*  ms_to_ticks_ceil()                                                */
/*  Convert milliseconds to Contiki clock ticks, rounding up.        */
/*  Guarantees at least 1 tick to prevent zero-delay ctimers.        */
/* ------------------------------------------------------------------ */
static clock_time_t
ms_to_ticks_ceil(uint32_t ms)
{
    clock_time_t t = (clock_time_t)
        ((ms * (uint32_t)CLOCK_SECOND + 999u) / 1000u);
    return (t == 0) ? (clock_time_t)1 : t;
}

/* ------------------------------------------------------------------ */
/*  Fan-out context (broadcast with jitter retries)                   */
/* ------------------------------------------------------------------ */
typedef struct {
    uint8_t  buf[DUMB_MAX_FRAME];
    uint16_t len;
    uint8_t  remaining;
    struct simple_udp_connection *udp;
    struct ctimer timer;
    uip_ipaddr_t maddr;
} fanout_ctx_t;

static void fanout_cb(void *ptr); /* forward */

static void
start_broadcast_fanout(fanout_ctx_t *ctx,
                       struct simple_udp_connection *conn,
                       const uint8_t *frame, uint16_t len,
                       uint8_t fanout)
{
    uip_create_linklocal_allnodes_mcast(&ctx->maddr);
    ctx->udp = conn;
    if(len > sizeof(ctx->buf)) len = (uint16_t)sizeof(ctx->buf);
    ctx->len = len;
    memcpy(ctx->buf, frame, len);

    simple_udp_sendto(ctx->udp, ctx->buf, ctx->len, &ctx->maddr);

    if(fanout <= 1) { ctx->remaining = 0; return; }
    ctx->remaining = (uint8_t)(fanout - 1);
    ctimer_set(&ctx->timer, ms_to_ticks_ceil(dumb_rand_jitter_ms()),
               fanout_cb, ctx);
}

static void
fanout_cb(void *ptr)
{
    fanout_ctx_t *ctx = (fanout_ctx_t *)ptr;
    if(ctx->remaining == 0) return;
    simple_udp_sendto(ctx->udp, ctx->buf, ctx->len, &ctx->maddr);
    ctx->remaining--;
    if(ctx->remaining)
        ctimer_set(&ctx->timer, ms_to_ticks_ceil(dumb_rand_jitter_ms()),
                   fanout_cb, ctx);
}

/* Separate fanout contexts so EF and DATA never overwrite each other. */
static fanout_ctx_t ef_fanout_ctx;
static fanout_ctx_t data_fanout_ctx;

/* ------------------------------------------------------------------ */
/*  Node identity & RSU state                                         */
/* ------------------------------------------------------------------ */
static uint8_t  node_id8;
static uint32_t origin_id;
static uint16_t seq16    = 0;
static uip_ipaddr_t rsu_ip;
static uint32_t rsu_id   = 0;
static uint8_t  have_rsu = 0;

/* ------------------------------------------------------------------ */
/*  QUERY/ACK epoch (3-misses rule for RSU visibility)                */
/* ------------------------------------------------------------------ */
static uint32_t probe_epoch    = 0;
static uint32_t ack_epoch_last = 0;

/* ------------------------------------------------------------------ */
/*  Dedup & compact carry store                                        */
/* ------------------------------------------------------------------ */
static dumb_dedup_t dedup;
static dumb_carry_t carry;
static uint8_t      carry_flush_active = 0;

/* ------------------------------------------------------------------ */
/*  Location & motion state                                           */
/* ------------------------------------------------------------------ */
static uint32_t last_ts_ms     = 0;
static uint8_t  have_loc       = 0;
static int32_t  loc_x_dm       = 0;
static int32_t  loc_y_dm       = 0;
static int32_t  prev_x_dm      = 0;
static int32_t  prev_y_dm      = 0;
static uint8_t  have_pos       = 0;
static uint32_t t_last_move_ms = 0;
static uint16_t v_dmps         = 0;
static uint8_t  dir8           = DUMB_DIR_UNK;
static uint8_t  ef_active      = 0;

#define STOP_THRESH_DM  1       /* <= 1 dm displacement -> "still" */
#define STOP_MIN_MS     2000    /* must be still >= 2 s to trigger EF */

/* ------------------------------------------------------------------ */
/*  Periodic timers                                                   */
/* ------------------------------------------------------------------ */
static struct etimer t_query;
static struct etimer t_gossip;
static struct etimer t_rsu_data;
static struct etimer t_loc;

/* ------------------------------------------------------------------ */
/*  Friend list (long-lived, persists across messages)                */
/*                                                                    */
/*  friend_id[]:   two friend OriginIDs, or DUMB_FRIEND_EMPTY.       */
/* ------------------------------------------------------------------ */
static uint32_t friend_id[2]   = { DUMB_FRIEND_EMPTY, DUMB_FRIEND_EMPTY };

/* ------------------------------------------------------------------ */
/*  Originated-DATA retry context                                     */
/*                                                                    */
/*  Stores the frozen identity and metric snapshot for the current    */
/*  originated DATA message. The DUMB frame is rebuilt for each retry */
/*  from these fields plus the live friend_id[] — so retries always   */
/*  carry the latest friend list while keeping msg_id and ts_ms       */
/*  unchanged.                                                        */
/* ------------------------------------------------------------------ */
typedef struct {
    uint32_t msg_id;        /* frozen at creation */
    uint32_t ts_ms;         /* frozen at creation */
    int16_t  x_dm;          /* metric snapshot (creator's position) */
    int16_t  y_dm;
    uint16_t v_dmps;
    uint8_t  dir8;
    int8_t   rssi_dbm;
    uint8_t  ttl8;          /* DATA hop budget as created (do not change on retries) */
    uint8_t  ack_mask;      /* bit0=friend[0] ACKed, bit1=friend[1] ACKed */
    uint8_t  retry_count;   /* transmissions completed so far (starts at 1) */
    uint8_t  active;        /* 1 while retry cycle is running */
} data_retry_ctx_t;

static data_retry_ctx_t dctx;

/*
 * Candidate senders collected during the current ACK window.
 * Only accepted when at least one friend slot is empty.
 * Promoted to friend_id[] only at the end of the ACK window.
 */
static uint8_t  cand_seen  = 0;
static uint32_t cand_id[2] = { DUMB_FRIEND_EMPTY, DUMB_FRIEND_EMPTY };

/* ------------------------------------------------------------------ */
/*  EF LED                                                            */
/* ------------------------------------------------------------------ */
static uint8_t ef_led_on = 0;

static void
ef_led_set(uint8_t on)
{
    ef_led_on = on ? 1 : 0;
    if(ef_led_on) leds_on(LEDS_RED);
    else          leds_off(LEDS_RED);
}

/* ------------------------------------------------------------------ */
/*  EF registry                                                       */
/* ------------------------------------------------------------------ */
#define EF_TAB_MAX 8

typedef struct {
    uint8_t  in_use;
    uint32_t origin;
    uint8_t  code;
    uint32_t tick;
} ef_entry_t;

static ef_entry_t ef_tab[EF_TAB_MAX];
static uint32_t   ef_tick = 0;

static uint8_t
ef_count_active(void)
{
    uint8_t n = 0;
    for(uint8_t i = 0; i < EF_TAB_MAX; ++i) n += (ef_tab[i].in_use != 0);
    return n;
}

static void
ef_led_refresh(void)
{
    ef_led_set(ef_count_active() ? 1 : 0);
}

static int8_t
ef_find(uint32_t origin)
{
    for(uint8_t i = 0; i < EF_TAB_MAX; ++i)
        if(ef_tab[i].in_use && ef_tab[i].origin == origin)
            return (int8_t)i;
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
    int8_t free_i  = -1;
    uint32_t min_t = 0xFFFFFFFFu;
    int8_t old_i   = -1;
    for(uint8_t i = 0; i < EF_TAB_MAX; ++i) {
        if(!ef_tab[i].in_use && free_i < 0) free_i = (int8_t)i;
        if(ef_tab[i].in_use && ef_tab[i].tick < min_t) {
            min_t = ef_tab[i].tick; old_i = (int8_t)i;
        }
    }
    int8_t put = (free_i >= 0) ? free_i : old_i;
    ef_tab[put].in_use = 1;
    ef_tab[put].origin = origin;
    ef_tab[put].code   = code;
    ef_tab[put].tick   = ++ef_tick;
}

static void
ef_remove(uint32_t origin)
{
    int8_t idx = ef_find(origin);
    if(idx >= 0) ef_tab[idx].in_use = 0;
}

static uint8_t
ef_get_last(uint32_t *out_origin, uint8_t *out_code)
{
    int8_t best = -1;
    uint32_t best_tick = 0;
    for(uint8_t i = 0; i < EF_TAB_MAX; ++i) {
        if(ef_tab[i].in_use && ef_tab[i].tick >= best_tick) {
            best_tick = ef_tab[i].tick; best = (int8_t)i;
        }
    }
    if(best < 0) return 0;
    if(out_origin) *out_origin = ef_tab[best].origin;
    if(out_code)   *out_code   = ef_tab[best].code;
    return 1;
}

static uint8_t
ef_self_active(void)
{
    for(uint8_t i = 0; i < EF_TAB_MAX; ++i)
        if(ef_tab[i].in_use && ef_tab[i].origin == origin_id) return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  UART helper                                                       */
/* ------------------------------------------------------------------ */
static void
uart1_puts_ln(const char *s)
{
    if(!s) return;
    while(*s) uart1_writeb((uint8_t)*s++);
    uart1_writeb('\n');
}

/* ------------------------------------------------------------------ */
/*  Integer hypotenuse approximation (no sqrt, no float)              */
/* ------------------------------------------------------------------ */
static uint32_t
ihyp_dm(uint32_t adx, uint32_t ady)
{
    return adx + (ady >> 1);
}

/* ------------------------------------------------------------------ */
/*  pack_metrics()                                                    */
/*  Write x,y,v,dir into the first 7 bytes of a DATA payload buffer. */
/*  Layout is little-endian (matches dumb_data_payload_t fields).     */
/* ------------------------------------------------------------------ */
static void
pack_metrics(uint8_t out[7])
{
    int16_t  x = (int16_t)loc_x_dm;
    int16_t  y = (int16_t)loc_y_dm;
    uint16_t v = v_dmps;
    out[0] = (uint8_t)(x & 0xFF);
    out[1] = (uint8_t)((x >> 8) & 0xFF);
    out[2] = (uint8_t)(y & 0xFF);
    out[3] = (uint8_t)((y >> 8) & 0xFF);
    out[4] = (uint8_t)(v & 0xFF);
    out[5] = (uint8_t)((v >> 8) & 0xFF);
    out[6] = dir8;
}

/* ------------------------------------------------------------------ */
/*  Friend list helpers                                               */
/* ------------------------------------------------------------------ */

/* Return 1 if both friend slots are occupied. */
static uint8_t
friend_list_full(void)
{
    return (friend_id[0] != DUMB_FRIEND_EMPTY &&
            friend_id[1] != DUMB_FRIEND_EMPTY) ? 1 : 0;
}

/* Write current friend_id[] values into a DATA payload struct. */
static void
friend_list_write(dumb_data_payload_t *pl)
{
    dumb_u32_be_write(pl->friend1_be, friend_id[0]);
    dumb_u32_be_write(pl->friend2_be, friend_id[1]);
}

/* Extract friend IDs from a received DATA payload raw buffer. */
static void
friend_list_read(const uint8_t *pl, uint16_t pl_len, uint32_t out_f[2])
{
    out_f[0] = DUMB_FRIEND_EMPTY;
    out_f[1] = DUMB_FRIEND_EMPTY;
    if(pl == NULL || pl_len < sizeof(dumb_data_payload_t)) return;
    out_f[0] = dumb_u32_be_read(&pl[8]);
    out_f[1] = dumb_u32_be_read(&pl[12]);
}

static uint16_t candidate_data[] = {0,0};

static uint8_t
is_my_friend(uint32_t id)
{
    return (id != DUMB_FRIEND_EMPTY &&
            (id == friend_id[0] || id == friend_id[1])) ? 1 : 0;
}

/*
static uint8_t
friend_list_contains_my_friend(const uint32_t rf[2])
{
    for(int i = 0; i < 2; ++i) {
        if(rf[i] == DUMB_FRIEND_EMPTY) continue;
        if(rf[i] == friend_id[0] || rf[i] == friend_id[1]) return 1;
    }
    return 0;
}
*/

/* ------------------------------------------------------------------ */
/*  Candidate filtering                                               */
/* ------------------------------------------------------------------ */
/*
static uint8_t
dir_similar(uint8_t a, uint8_t b)
{
    if(a > 7 || b > 7) return 0;
    uint8_t d = (a > b) ? (uint8_t)(a - b) : (uint8_t)(b - a);
    if(d > 4) d = (uint8_t)(8u - d);
    return (d <= 1) ? 1 : 0;
}
*/ // Allow friends from the other dimension

static uint8_t
candidate_ok(const uint8_t *pl, uint16_t pl_len)
{
    if(friend_id[0] == DUMB_FRIEND_EMPTY &&
       friend_id[1] == DUMB_FRIEND_EMPTY) return 1; // Allow first candidate
    if(pl == NULL || pl_len < sizeof(dumb_data_payload_t)) return 0;
    // int16_t  sx  = (int16_t)((uint16_t)pl[0] | ((uint16_t)pl[1] << 8));
    // int16_t  sy  = (int16_t)((uint16_t)pl[2] | ((uint16_t)pl[3] << 8));
    uint16_t sv  = (uint16_t)((uint16_t)pl[4] | ((uint16_t)pl[5] << 8));
    candidate_data[0] = sv;
    // uint8_t  sdir = pl[6];
    // int32_t  dx  = (int32_t)sx - loc_x_dm;
    // int32_t  dy  = (int32_t)sy - loc_y_dm;
    // uint32_t adx = (dx >= 0) ? (uint32_t)dx : (uint32_t)(-dx);
    // uint32_t ady = (dy >= 0) ? (uint32_t)dy : (uint32_t)(-dy);
    uint16_t dv  = (sv > v_dmps) ? (sv - v_dmps) : (v_dmps - sv);
    candidate_data[1] = v_dmps;
    // if(adx + ady > DUMB_FRIEND_DIST_DM) return 0;
    if(dv        > DUMB_FRIEND_DV_DMPS) return 0;
    // if(!dir_similar(sdir, dir8))        return 0; // Allow friends going the other way
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Delayed ACK sender (anti-jitter for candidate ACKs)              */
/* ------------------------------------------------------------------ */
typedef struct {
    uip_ipaddr_t dst;
    uint32_t target_id;
    uint32_t ts_ms;
    uint8_t  acked_type;
    uint32_t acked_origin;
    uint32_t acked_msg;
    struct ctimer t;
    uint8_t  in_use;
    uint8_t use_mcast;
} ack_delay_ctx_t;

static ack_delay_ctx_t ack_ctx;

static void
ack_delay_cb(void *ptr)
{
    ack_delay_ctx_t *a = (ack_delay_ctx_t *)ptr;
    if(!a || !a->in_use) return;

    if(a->use_mcast) {
        send_ack_mcast(a->target_id, a->ts_ms,
                       a->acked_type, a->acked_origin, a->acked_msg);
    } else {
        send_ack_unicast(&a->dst, a->target_id, a->ts_ms,
                         a->acked_type, a->acked_origin, a->acked_msg);
    }

    a->in_use = 0;
}

static void
schedule_ack(const uip_ipaddr_t *dst,
             uint32_t target_id, uint32_t ts_ms,
             uint8_t acked_type, uint32_t acked_origin,
             uint32_t acked_msg, uint8_t use_mcast)

{
    if(!dst) return;
    if(ack_ctx.in_use) {
        /* Slot busy: send immediately to avoid dropping the ACK. */
        if(use_mcast) {
            send_ack_mcast(target_id, ts_ms,
                           acked_type, acked_origin, acked_msg);
        } else {
            send_ack_unicast(dst, target_id, ts_ms,
                             acked_type, acked_origin, acked_msg);
        }

        return;
    }
    ack_ctx.dst          = *dst;
    ack_ctx.target_id    = target_id;
    ack_ctx.ts_ms        = ts_ms;
    ack_ctx.acked_type   = acked_type;
    ack_ctx.acked_origin = acked_origin;
    ack_ctx.acked_msg    = acked_msg;
    ack_ctx.in_use       = 1;
    ack_ctx.use_mcast = use_mcast;
    ctimer_set(&ack_ctx.t, ms_to_ticks_ceil(dumb_rand_jitter_ms()),
               ack_delay_cb, &ack_ctx);
}

/* ------------------------------------------------------------------ */
/*  carry_flush: rebuild wire frames and send to RSU                  */
/*                                                                    */
/*  Each in_use slot is serialized via dumb_pack() and unicast to     */
/*  the RSU. The RSU parses it with the standard dumb_parse() and     */
/*  ACKs it; the ACK handler calls dumb_carry_ack() to free the slot. */
/* ------------------------------------------------------------------ */
typedef struct {
    struct simple_udp_connection *udp;
    uip_ipaddr_t dest;
    uint16_t idx;
    uint16_t left;
    struct ctimer timer;
} carry_flush_ctx_t;

static carry_flush_ctx_t cflush;

static uint8_t
carry_has_pending(void)
{
	
    return 0; // DUMB: always empty
	
    for(uint16_t i = 0; i < DUMB_CARRY_MAX_ITEMS; ++i)
        if(carry.slots[i].in_use) return 1;
    return 0;
}

/*
 * carry_build_frame_for_rsu()
 * What:  Rebuild a full DUMB wire frame from a compact carry slot,
 *        targeted at the RSU (unicast, SenderID = self, OriginID = creator).
 * Returns serialized length or 0 on error.
 */
static uint16_t
carry_build_frame_for_rsu(const dumb_carry_slot_t *s,
                           uint8_t *buf, uint16_t cap)
{

    /* DUMB: carry disabled */
    return 0;

    dumb_fields_t f;
    memset(&f, 0, sizeof(f));
    f.marker[0] = 'M'; f.marker[1] = 'b'; f.marker[2] = 'l';
    f.sender_id   = origin_id;      /* physical sender = this node */
    f.origin_id   = s->origin_id;   /* logical creator preserved */
    f.msg_id      = s->msg_id;
    f.ts_ms       = s->ts_ms;
    f.target_id   = rsu_id;

    if(s->msg_type == DUMB_MSG_DATA) {
        f.msg_type = DUMB_MSG_DATA;
        dumb_data_payload_t pl;
        pl.x_dm     = s->x_dm;
        pl.y_dm     = s->y_dm;
        pl.v_dmps   = s->v_dmps;
        pl.dir8     = s->dir8;
        pl.rssi_dbm = s->rssi_dbm;
        pl.ttl8     = s->ttl8; /* Preserve creator TTL; flush is not a hop */
        /* Friend list not needed for RSU delivery; send as EMPTY. */
        dumb_u32_be_write(pl.friend1_be, DUMB_FRIEND_EMPTY);
        dumb_u32_be_write(pl.friend2_be, DUMB_FRIEND_EMPTY);
        f.payload     = (const uint8_t *)&pl;
        f.payload_len = (uint16_t)sizeof(pl);

    } else if(s->msg_type == DUMB_MSG_EMERGENCY) {
        f.msg_type = DUMB_MSG_EMERGENCY;
        static uint8_t ef_pl[12];  /* static: avoid stack pressure */
        ef_pl[0] = 'E'; ef_pl[1] = 'F'; ef_pl[2] = 'B'; ef_pl[3] = 'R';
        ef_pl[4] = s->ef_code;
        ef_pl[5]  = (uint8_t)(s->x_dm & 0xFF);
        ef_pl[6]  = (uint8_t)((s->x_dm >> 8) & 0xFF);
        ef_pl[7]  = (uint8_t)(s->y_dm & 0xFF);
        ef_pl[8]  = (uint8_t)((s->y_dm >> 8) & 0xFF);
        ef_pl[9]  = (uint8_t)(s->v_dmps & 0xFF);
        ef_pl[10] = (uint8_t)((s->v_dmps >> 8) & 0xFF);
        ef_pl[11] = s->dir8;
        f.payload     = ef_pl;
        f.payload_len = sizeof(ef_pl);
    } else {
        return 0;   /* unknown type; skip */
    }

    uint16_t out_len = 0;
    if(!dumb_pack(&f, buf, cap, &out_len)) return 0;
    return out_len;
}

static void
carry_flush_cb(void *ptr)
{
	
    /* DUMB: carry disabled */
    return;

    carry_flush_ctx_t *cf = (carry_flush_ctx_t *)ptr;

    while(cf->left > 0) {
        uint16_t i = (uint16_t)(cf->idx % DUMB_CARRY_MAX_ITEMS);
        cf->idx++;
        cf->left--;

        dumb_carry_slot_t *s = &carry.slots[i];
        if(!s->in_use) continue;

        uint8_t buf[DUMB_MAX_FRAME];
        uint16_t len = carry_build_frame_for_rsu(s, buf, sizeof(buf));
        if(len == 0) continue;

#if DUMB_DIAG
        printf("%lu,CARRY_TX,slot=%u,left=%u,bytes=%u\n",
               (unsigned long)clock_seconds(),
               (unsigned)i, (unsigned)cf->left, (unsigned)len);
#endif
        simple_udp_sendto(cf->udp, buf, len, &cf->dest);
        ctimer_set(&cf->timer, ms_to_ticks_ceil(5), carry_flush_cb, cf);
        return;
    }

    /* Scan done: if no slots remain, reset the ring counters. */
    if(!carry_has_pending()) dumb_carry_init(&carry);
    carry_flush_active = 0;
}

static void
start_carry_flush(void)
{

    /* DUMB: carry disabled, no flush */
    return;

    if(!have_rsu)              return;
    if(carry_flush_active)     return;
    if(!carry_has_pending())   return;
    cflush.udp  = &udp;
    cflush.dest = rsu_ip;
    cflush.idx  = 0;
    cflush.left = DUMB_CARRY_MAX_ITEMS;
    carry_flush_active = 1;
    carry_flush_cb(&cflush);
}

/* ------------------------------------------------------------------ */
/*  send_ack_unicast()                                                */
/* ------------------------------------------------------------------ */
static void
send_ack_unicast(const uip_ipaddr_t *dst,
                 uint32_t target_id,
                 uint32_t ts_ms,
                 uint8_t  acked_type,
                 uint32_t acked_origin,
                 uint32_t acked_msg)
{
    (void)dst;  // Multicast ACK
    dumb_fields_t f;
    memset(&f, 0, sizeof(f));
    f.marker[0] = 'M'; f.marker[1] = 'b'; f.marker[2] = 'l';
    f.sender_id   = origin_id;
    f.origin_id   = origin_id;
    f.msg_type    = DUMB_MSG_ACK;
    f.msg_id      = dumb_make_msgid(&seq16);
    f.target_id   = target_id;
    f.ts_ms       = ts_ms;

    uint8_t pl[9];
    pl[0] = acked_type;
    dumb_u32_be_write(&pl[1], acked_origin);
    dumb_u32_be_write(&pl[5], acked_msg);
    f.payload     = pl;
    f.payload_len = sizeof(pl);

    uint8_t buf[DUMB_MAX_FRAME];
    uint16_t out_len = 0;
    if(!dumb_pack(&f, buf, sizeof(buf), &out_len)) return;
    simple_udp_sendto(&udp, buf, out_len, dst);

#if FRIEND_LIST_MONITOR_ENABLED
            printf("MBL: ACKing DIRECTLY MsgID=%lu from mote#%lu.\n",(unsigned long)acked_msg, (unsigned long)target_id);
#endif
    
}

static void
send_ack_mcast(uint32_t target_id,
               uint32_t ts_ms,
               uint8_t  acked_type,
               uint32_t acked_origin,
               uint32_t acked_msg)
{
    dumb_fields_t f;
    memset(&f, 0, sizeof(f));
    f.marker[0] = 'M'; f.marker[1] = 'b'; f.marker[2] = 'l';
    f.sender_id   = origin_id;
    f.origin_id   = origin_id;
    f.msg_type    = DUMB_MSG_ACK;
    f.msg_id      = dumb_make_msgid(&seq16);
    f.target_id   = target_id;
    f.ts_ms       = ts_ms;

    uint8_t pl[9];
    pl[0] = acked_type;
    dumb_u32_be_write(&pl[1], acked_origin);
    dumb_u32_be_write(&pl[5], acked_msg);
    f.payload     = pl;
    f.payload_len = (uint16_t)sizeof(pl);

    uint8_t buf[DUMB_MAX_FRAME];
    uint16_t out_len = 0;
    if(!dumb_pack(&f, buf, sizeof(buf), &out_len)) return;

    uip_ipaddr_t maddr;
    uip_create_linklocal_allnodes_mcast(&maddr);
    simple_udp_sendto(&udp, buf, out_len, &maddr);

#if FRIEND_LIST_MONITOR_ENABLED
            printf("MBL: ACKing BROADCAST MsgID=%lu from mote#%lu.\n",(unsigned long)acked_msg, (unsigned long)target_id);
#endif

}

/* ------------------------------------------------------------------ */
/*  send_emergency()                                                  */
/* ------------------------------------------------------------------ */
static void
send_emergency(uint8_t ef_code)
{
    dumb_fields_t f;
    memset(&f, 0, sizeof(f));
    f.marker[0] = 'M'; f.marker[1] = 'b'; f.marker[2] = 'l';
    f.sender_id   = origin_id;
    f.origin_id   = origin_id;
    f.msg_type    = DUMB_MSG_EMERGENCY;
    f.msg_id      = dumb_make_msgid(&seq16);
    f.target_id   = DUMB_TGT_BROADCAST;
    f.ts_ms       = last_ts_ms;

    uint8_t pl[12] = { 'E', 'F', 'B', 'R', ef_code };
    pack_metrics(&pl[5]);
    f.payload     = pl;
    f.payload_len = sizeof(pl);

    uint8_t buf[DUMB_MAX_FRAME];
    uint16_t out_len = 0;
    if(!dumb_pack(&f, buf, sizeof(buf), &out_len)) return;

#if DUMB_METRIC_LOG_ENABLED
    if(ef_code != DUMB_EF_FINISH)
        printf("Emergency Issued: id=%lu code=%u\n",
               (unsigned long)origin_id, (unsigned)ef_code);
    else
        printf("Emergency Finished: id=%lu\n", (unsigned long)origin_id);
    printf("MBL_TX type=EF origin=%lu msg=%lu code=%u "
           "x=%ld y=%ld v=%u dir=%u ts=%lu\n",
           (unsigned long)origin_id, (unsigned long)f.msg_id,
           (unsigned)ef_code,
           (long)(int16_t)((uint16_t)pl[5]  | ((uint16_t)pl[6]  << 8)),
           (long)(int16_t)((uint16_t)pl[7]  | ((uint16_t)pl[8]  << 8)),
           (unsigned)((uint16_t)pl[9] | ((uint16_t)pl[10] << 8)),
           (unsigned)pl[11],
           (unsigned long)last_ts_ms);
#endif

    start_broadcast_fanout(&ef_fanout_ctx, &udp, buf, out_len, DUMB_FANOUT_EF);

/*  if(!dumb_carry_exists(&carry, f.origin_id, f.msg_id))
        carry_store(DUMB_MSG_EMERGENCY,
                    f.origin_id, f.msg_id, f.ts_ms,
                    (int16_t)loc_x_dm, (int16_t)loc_y_dm,
                    v_dmps, dir8, 0, 0, ef_code);
*/
    if(have_rsu && carry_has_pending()) start_carry_flush();
}

/* ------------------------------------------------------------------ */
/*  parse_loc_line()                                                  */
/*  Parse "LOC id x_dm y_dm ts_ms" from UART. Update position,       */
/*  speed, direction. Detect stop/start; send EF / EF_FINISH.        */
/* ------------------------------------------------------------------ */
static uint8_t
parse_loc_line(const char *line)
{
    if(!line) return 0;
    while(*line == ' ') line++;
    if(line[0]!='L' || line[1]!='O' || line[2]!='C') return 0;

    const char *p = line + 3;
    while(*p == ' ') p++;

#if LOC_PRINT
    long parsed_id = strtol(p, (char **)&p, 10); while(*p==' ') p++;
#else
    (void)strtol(p, (char **)&p, 10); while(*p==' ') p++;
#endif
    int32_t  xdm = (int32_t)strtol (p, (char **)&p, 10); while(*p==' ') p++;
    int32_t  ydm = (int32_t)strtol (p, (char **)&p, 10); while(*p==' ') p++;
    uint32_t ts  = (uint32_t)strtoul(p, (char **)&p, 10);

#if LOC_PRINT
    printf("LOC_RX: self=%lu parsed_id=%ld x=%ld y=%ld ts=%lu\n",
           (unsigned long)origin_id, parsed_id,
           (long)xdm, (long)ydm, (unsigned long)ts);
#endif

    uint32_t prev_ts = last_ts_ms;
    last_ts_ms = ts;
    have_loc   = 1;

    if(!have_pos) {
        prev_x_dm = loc_x_dm = xdm;
        prev_y_dm = loc_y_dm = ydm;
        t_last_move_ms = ts;
        v_dmps = 0; dir8 = DUMB_DIR_UNK;
        have_pos = 1;
        return 1;
    }

    int32_t  dx  = xdm - loc_x_dm;
    int32_t  dy  = ydm - loc_y_dm;
    uint32_t adx = (dx >= 0) ? (uint32_t)dx : (uint32_t)(-dx);
    uint32_t ady = (dy >= 0) ? (uint32_t)dy : (uint32_t)(-dy);

    prev_x_dm = loc_x_dm; prev_y_dm = loc_y_dm;
    loc_x_dm  = xdm;      loc_y_dm  = ydm;

    uint8_t nd = dumb_dir_from_delta(dx, dy);
    if(nd != DUMB_DIR_UNK) dir8 = nd;

    uint32_t dt_ms = (ts >= prev_ts) ? (ts - prev_ts) : 0;
    if(dt_ms == 0) dt_ms = 1;
    v_dmps = (uint16_t)((ihyp_dm(adx, ady) * 1000u) / dt_ms);

    uint32_t man = adx + ady;
    if(man > STOP_THRESH_DM) {
        t_last_move_ms = ts;
        if(ef_active) {
            send_emergency(DUMB_EF_FINISH);
            ef_active = 0;
            ef_led_set(0);
            ef_remove(origin_id);
            ef_led_refresh();
        }
    } else {
        if(!ef_active) {
            uint32_t stood = (ts >= t_last_move_ms) ?
                             (ts - t_last_move_ms) : 0;
            if(stood >= STOP_MIN_MS) {
                if(!ef_self_active()) {
                    uint8_t foreign = 0;
                    for(uint8_t i = 0; i < EF_TAB_MAX; ++i)
                        if(ef_tab[i].in_use && ef_tab[i].origin != origin_id)
                            { foreign = 1; break; }
                    if(foreign) {
#if DUMB_METRIC_LOG_ENABLED
                        printf("EF_SUPPRESSED: id=%lu (foreign EF active)\n",
                               (unsigned long)origin_id);
#endif
                    } else {
                        send_emergency(1);
                        ef_active = 1;
                        ef_led_set(1);
                        ef_add_or_update(origin_id, 1);
                        ef_led_refresh();
                    }
                }
            }
        }
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Unicast DATA to RSU with ctimer retries                           */
/* ------------------------------------------------------------------ */
typedef struct {
    uint8_t  buf[DUMB_MAX_FRAME];
    uint16_t len;
    uint8_t  remaining;
    struct simple_udp_connection *udp;
    struct ctimer timer;
    uip_ipaddr_t dest;
} unicast_retry_ctx_t;

static unicast_retry_ctx_t uctx;

static void
unicast_retry_cb(void *ptr)
{
    unicast_retry_ctx_t *c = (unicast_retry_ctx_t *)ptr;
    if(c->remaining == 0) return;
    simple_udp_sendto(c->udp, c->buf, c->len, &c->dest);
    c->remaining--;
    if(c->remaining)
        ctimer_set(&c->timer, ms_to_ticks_ceil(dumb_rand_jitter_ms()),
                   unicast_retry_cb, c);
}

static void
start_unicast_with_retries(struct simple_udp_connection *conn,
                           const uip_ipaddr_t *dest,
                           const uint8_t *frame, uint16_t len,
                           uint8_t retries_total)
{
    uctx.udp  = conn;
    uctx.len  = len;
    memcpy(uctx.buf, frame, len);
    uctx.dest = *dest;
    simple_udp_sendto(uctx.udp, uctx.buf, uctx.len, &uctx.dest);
    if(retries_total <= 1) { uctx.remaining = 0; return; }
    uctx.remaining = (uint8_t)(retries_total - 1);
    ctimer_set(&uctx.timer, ms_to_ticks_ceil(dumb_rand_jitter_ms()),
               unicast_retry_cb, &uctx);
}

/* ------------------------------------------------------------------ */
/*  send_query()                                                      */
/* ------------------------------------------------------------------ */
static void
send_query(void)
{
    dumb_fields_t f;
    memset(&f, 0, sizeof(f));
    f.marker[0] = 'M'; f.marker[1] = 'b'; f.marker[2] = 'l';
    f.sender_id   = origin_id;
    f.origin_id   = origin_id;
    f.msg_type    = DUMB_MSG_QUERY;
    f.msg_id      = dumb_make_msgid(&seq16);
    f.target_id   = DUMB_TGT_BROADCAST;
    f.ts_ms       = last_ts_ms;

    uint8_t qpl[5];
    uint32_t ef_orig = 0; uint8_t ef_flag = 0;
    if(!ef_get_last(&ef_orig, &ef_flag)) { ef_orig = 0; ef_flag = 0; }
    qpl[0] = ef_flag;
    dumb_u32_be_write(&qpl[1], ef_orig);
    f.payload     = qpl;
    f.payload_len = sizeof(qpl);

    uint8_t buf[DUMB_MAX_FRAME];
    uint16_t out_len = 0;
    if(!dumb_pack(&f, buf, sizeof(buf), &out_len)) return;
    fanout_ctx_t tmp;
    start_broadcast_fanout(&tmp, &udp, buf, out_len, 1);

#if DUMB_DIAG
    printf("%lu,QUERY,ef=%u,ef_orig=%lu\n",
           (unsigned long)clock_seconds(),
           (unsigned)ef_flag, (unsigned long)ef_orig);
#endif
}

/* ------------------------------------------------------------------ */
/*  send_data_unicast_to_rsu()                                        */
/*  Send own current DATA directly to RSU (when RSU is visible).     */
/*  Also stores in carry so it survives until ACKed.                  */
/* ------------------------------------------------------------------ */
static void
send_data_unicast_to_rsu(uint32_t msg_id)
{
    if(!have_rsu || !have_loc) return;

    dumb_data_payload_t pl;
    pack_metrics((uint8_t *)&pl);
    pl.rssi_dbm = 0;
    friend_list_write(&pl);
    pl.ttl8 = DUMB_DATA_TTL_DEFAULT;

    dumb_fields_t f;
    memset(&f, 0, sizeof(f));
    f.marker[0] = 'M'; f.marker[1] = 'b'; f.marker[2] = 'l';
    f.sender_id   = origin_id;
    f.origin_id   = origin_id;
    f.msg_type    = DUMB_MSG_DATA;
    f.msg_id      = msg_id;
    f.target_id   = rsu_id;
    f.payload     = (const uint8_t *)&pl;
    f.payload_len = (uint16_t)sizeof(pl);
    f.ts_ms       = last_ts_ms;

    uint8_t buf[DUMB_MAX_FRAME];
    uint16_t out_len = 0;
    if(!dumb_pack(&f, buf, sizeof(buf), &out_len)) return;

    start_unicast_with_retries(&udp, &rsu_ip, buf, out_len,
                               DUMB_UNICAST_RETRIES);
#if DUMB_METRIC_LOG_ENABLED
    printf("MBL TX origin=%lu msg=%lu hop=0 len=%u\n",
           origin_id, msg_id,
           (unsigned)sizeof(dctx));
#endif // DUMB_METRIC_LOG_ENABLED

}

/* ------------------------------------------------------------------ */
/*  start_gossip_data()                                               */
/*                                                                    */
/*  Originate a new gossip DATA message:                              */
/*  - Freeze msg_id and ts_ms into dctx (never change across retries).*/
/*  - Snapshot current metrics into dctx.                             */
/*  - Build first frame (with current friend list) and broadcast.     */
/*  - Store compact record in carry.                                  */
/*  - Start the ACK window timer.                                     */
/* ------------------------------------------------------------------ */
static void
start_gossip_data(void)
{

    /* ========= CREATE ========= */
    dctx.msg_id = dumb_make_msgid(&seq16);
    dctx.ts_ms  = last_ts_ms;

#if DUMB_METRIC_LOG_ENABLED
    printf("CREATE origin=%lu msg=%lu time=%lu gossip\n",
           (unsigned long)origin_id,
           (unsigned long)dctx.msg_id,
           (unsigned long)dctx.ts_ms);
#endif // DUMB_METRIC_LOG_ENABLED


    /* === DUMB: NO GOSSIP === */

    /* === ALWAYS TRY RSU === */
    if(have_rsu) {
        send_data_unicast_to_rsu(dctx.msg_id);

	}
}
/* ------------------------------------------------------------------ */
/*  UDP RX callback                                                   */
/* ------------------------------------------------------------------ */
static void
udp_rx_cb(struct simple_udp_connection *c,
          const uip_ipaddr_t *sender_addr,
          uint16_t sender_port,
          const uip_ipaddr_t *receiver_addr,
          uint16_t receiver_port,
          const uint8_t *data, uint16_t datalen)
{
    (void)c; (void)sender_port; (void)receiver_addr; (void)receiver_port;

    dumb_fields_t h;
    const uint8_t *pl = NULL;
    uint16_t pl_len   = 0;
    if(!dumb_parse(data, datalen, &h, &pl, &pl_len)) return;
    

    /* Dedup: DATA duplicates are still ACKed but not stored twice. */
    uint8_t is_dup = dumb_dedup_has(&dedup, h.origin_id, h.msg_id);
    if(is_dup) {
        if(h.msg_type != DUMB_MSG_DATA) return;
    } else {
        dumb_dedup_put(&dedup, h.origin_id, h.msg_id);
    }

    /* ---- RSU ACK ------------------------------------------------- */
    if(h.marker[0]=='R' && h.marker[1]=='S' && h.marker[2]=='U') {
        if(h.msg_type != DUMB_MSG_ACK) return;

        rsu_ip         = *sender_addr;
        rsu_id         = h.origin_id;
        have_rsu       = 1;
        ack_epoch_last = probe_epoch;

        /* Learn emergency state propagated by RSU in ACK payload. */
        if(pl && pl_len >= 14) {
            uint8_t  ef_code   = pl[9];
            uint32_t ef_origin = dumb_u32_be_read(&pl[10]);
            if(ef_origin != 0) {
                if(ef_code == DUMB_EF_FINISH)      ef_remove(ef_origin);
                else if(ef_code != DUMB_EF_NONE)   ef_add_or_update(ef_origin, ef_code);
                ef_led_refresh();
            }
        }

        /* Mark ACKed carry slot as free. */
        if(pl && pl_len >= 9) {
            uint32_t acked_origin = dumb_u32_be_read(&pl[1]);
            uint32_t acked_msg    = dumb_u32_be_read(&pl[5]);
            dumb_carry_ack(&carry, acked_origin, acked_msg);
        }

        ctimer_stop(&uctx.timer); uctx.remaining = 0;
        if(carry_has_pending()) start_carry_flush();
        return;
    }

    /* ---- Mobile ACK ---------------------------------------------- */
    if(h.marker[0]=='M' && h.marker[1]=='b' && h.marker[2]=='l') {
        if(h.msg_type == DUMB_MSG_ACK) {
            if(pl && pl_len >= 9) {
                uint8_t  acked_type   = pl[0];
                uint32_t acked_origin = dumb_u32_be_read(&pl[1]);
                uint32_t acked_msg    = dumb_u32_be_read(&pl[5]);
                uint32_t a_sender     = h.sender_id;

                if(acked_type   == DUMB_MSG_DATA &&
                   acked_origin == origin_id     &&
                   acked_msg    == dctx.msg_id   &&
                   dctx.active) {

#if FRIEND_LIST_MONITOR_ENABLED
                   printf("MBL: Saw ACK for MsgID# %lu from %lu\n",(unsigned long)acked_msg, (unsigned long)a_sender);
#endif

                    /* Update ACK mask for existing friends. */
                    if(friend_id[0] != DUMB_FRIEND_EMPTY &&
                       a_sender == friend_id[0]) dctx.ack_mask |= 0x01u;
                    if(friend_id[1] != DUMB_FRIEND_EMPTY &&
                       a_sender == friend_id[1]) dctx.ack_mask |= 0x02u;

                    /*
                     * Candidate capture: only when at least one slot is empty.
                     * Accept up to two unique non-self senders.
                     * Promotion happens at end of ACK window, not here.
                     */
                    if(!friend_list_full()     &&
                       a_sender != origin_id   &&
                       cand_seen < 2           &&
                       a_sender != cand_id[0]  &&
                       a_sender != cand_id[1]) {
                        cand_id[cand_seen++] = a_sender;
                    }

/*
#if FRIEND_LIST_MONITOR_ENABLED
                    printf("DBG_RX_ACK self=%lu from=%lu msg=%lu "
                           "mask=0x%02x cand=%u f0=%lu f1=%lu clk=%lu\n",
                           (unsigned long)origin_id,
                           (unsigned long)a_sender,
                           (unsigned long)acked_msg,
                           (unsigned)dctx.ack_mask,
                           (unsigned)cand_seen,
                           (unsigned long)friend_id[0],
                           (unsigned long)friend_id[1],
                           (unsigned long)clock_time());
#endif
*/

                }
            }
            return;
        }
    }

    /* ---- Only Mobile frames beyond this point -------------------- */
    if(h.marker[0]!='M' || h.marker[1]!='b' || h.marker[2]!='l') return;

    /* ---- QUERY from another mobile ------------------------------- */
    if(h.msg_type == DUMB_MSG_QUERY) {
        if(pl && pl_len >= 5) {
            uint8_t  ef_flag = pl[0];
            uint32_t ef_orig = dumb_u32_be_read(&pl[1]);
            if(ef_flag == DUMB_EF_NONE) return;
            if(ef_find(ef_orig) < 0)    return;  /* accept only known origins */
            if(ef_flag == DUMB_EF_FINISH) ef_remove(ef_orig);
            else                          ef_add_or_update(ef_orig, ef_flag);
            ef_led_refresh();
#if DUMB_DIAG
            printf("%lu,QUERY_RX,from=%lu,ef=%u,ef_orig=%lu\n",
                   (unsigned long)clock_seconds(),
                   (unsigned long)h.origin_id,
                   (unsigned)ef_flag, (unsigned long)ef_orig);
#endif
        }
        return;
    }

    /* ---- DATA from another mobile -------------------------------- */
    if(h.msg_type == DUMB_MSG_DATA) {

#if DUMB_METRIC_LOG_ENABLED
        const dumb_data_payload_t *dpl = (const dumb_data_payload_t *)pl;
        printf("MBL RX origin=%lu msg=%lu hop=%u\n",
               (unsigned long)h.origin_id,
               (unsigned long)h.msg_id,
               (unsigned)(DUMB_DATA_TTL_DEFAULT - dpl->ttl8 + 1));
#endif

        uint32_t fl[2];
        friend_list_read(pl, pl_len, fl);

        uint8_t ttl = 0;
        if(pl_len >= sizeof(dumb_data_payload_t))
            ttl = ((const dumb_data_payload_t *)pl)->ttl8;

        /* Ignore if sender or their friend list overlaps ours. */

        if(is_my_friend(h.sender_id)) {
#if FRIEND_LIST_MONITOR_ENABLED
            printf("MBL: Not sending an ACK to MsgID#%lu sent by mote %lu, "
                   "because sender is my friend and is ACKing me.\n",
                   (unsigned long)h.msg_id,
                   (unsigned long)h.sender_id);
#endif
            return;
        }

/*
        if(friend_list_contains_my_friend(fl)) {
#if FRIEND_LIST_MONITOR_ENABLED
            printf("MBL: Not sending an ACK to MsgID#%lu sent by mote %lu, "
                   "because sender friend-list overlaps my friend(s)\n",
                   (unsigned long)h.msg_id,
                   (unsigned long)h.sender_id);
#endif
            return;
        }
*/

        uint8_t addressed_to_me =
            ((fl[0] != DUMB_FRIEND_EMPTY && fl[0] == origin_id) ||
             (fl[1] != DUMB_FRIEND_EMPTY && fl[1] == origin_id));
        uint8_t sender_list_full =
            (fl[0] != DUMB_FRIEND_EMPTY && fl[1] != DUMB_FRIEND_EMPTY);

        if(addressed_to_me) {
            /* We are a listed friend: ACK immediately (even on duplicate). */
            send_ack_unicast(sender_addr, h.sender_id, h.ts_ms,
                             h.msg_type, h.origin_id, h.msg_id);

            /* Forward with TTL-1 on first reception only.
             * Only sender_id and ttl8 change; all other fields preserved. */
            if(!is_dup && ttl > 0) {
                dumb_fields_t fwd        = h;
                dumb_data_payload_t pcopy;
                memcpy(&pcopy, pl, sizeof(pcopy));
                pcopy.ttl8       = (uint8_t)(ttl - 1);
                fwd.sender_id    = origin_id;  /* we are the physical forwarder */
                fwd.payload      = (const uint8_t *)&pcopy;
                fwd.payload_len  = (uint16_t)sizeof(pcopy);

                uint8_t buf2[DUMB_MAX_FRAME];
                uint16_t out2 = 0;
                if(dumb_pack(&fwd, buf2, sizeof(buf2), &out2))
                    start_broadcast_fanout(&data_fanout_ctx, &udp, buf2, out2, 1);
            }

            /* Store on first reception only.
             * Metrics come from the received payload (creator's values). */
            if(!is_dup && !dumb_carry_exists(&carry, h.origin_id, h.msg_id)) {
/*              const dumb_data_payload_t *dp =
                    (const dumb_data_payload_t *)pl;
                carry_store(DUMB_MSG_DATA,
                            h.origin_id, h.msg_id, h.ts_ms,
                            dp->x_dm, dp->y_dm, dp->v_dmps,
                            dp->dir8, dp->rssi_dbm, dp->ttl8, 0);
*/
            }
            if(have_rsu && carry_has_pending()) start_carry_flush();
            return;
        }


        /* Not addressed to us: ACK as candidate only if sender's list
         * is not full and candidate metrics match. */
        if(!sender_list_full && candidate_ok(pl, pl_len)) {
            schedule_ack(sender_addr, h.sender_id, h.ts_ms,
                         h.msg_type, h.origin_id, h.msg_id, 1);

        } else {
#if DUMB_DIAG
            if(sender_list_full) {
             /*   printf("MBL: Not sending ACK for MsgID#%lu, from mote %lu, "
                       "because sender friend-list is full\n",
                       (unsigned long)h.msg_id,
                       (unsigned long)h.sender_id);
                       */
            } else if(pl == NULL || pl_len < sizeof(dumb_data_payload_t)) {
                printf("MBL: Not sending an ACK to MsgID#%lu sent by mote %lu, "
                       "because payload is too short (%u bytes)\n",
                       (unsigned long)h.msg_id,
                       (unsigned long)h.sender_id,
                       (unsigned)pl_len);
            } else {
                printf("MBL: Not sending ACK for MsgID#%lu, from mote %lu, "
                       "because candidate_ok() failed. sv= %u, dv=%u.\n",
                       (unsigned long)h.msg_id,
                       (unsigned long)h.sender_id,
                       candidate_data[0],
                       candidate_data[1]);
            }
#endif
        }
        return;
    }

    /* ---- EMERGENCY from another mobile --------------------------- */
    if(h.msg_type == DUMB_MSG_EMERGENCY) {
        send_ack_unicast(sender_addr, h.origin_id, h.ts_ms,
                         h.msg_type, h.origin_id, h.msg_id);

        if(pl && pl_len >= 5) {
            if(pl[0]!='E'||pl[1]!='F'||pl[2]!='B'||pl[3]!='R') return;
            uint8_t efc     = pl[4];
            uint8_t src_dir = dir8;
            if(pl_len >= 12) src_dir = pl[5 + 6];

            if(efc != DUMB_EF_FINISH &&
               dir8 != DUMB_DIR_UNK  &&
               src_dir != dir8) return;

            ef_led_set(efc != DUMB_EF_FINISH);
            if(efc == DUMB_EF_FINISH) ef_remove(h.origin_id);
            else                      ef_add_or_update(h.origin_id, efc);
            ef_led_refresh();
        }

        start_broadcast_fanout(&ef_fanout_ctx, &udp, data, datalen,
                               DUMB_FANOUT_EF);
        if(have_rsu && carry_has_pending()) start_carry_flush();
        return;
    }
}

/* ------------------------------------------------------------------ */
/*  Process thread                                                    */
/* ------------------------------------------------------------------ */
PROCESS(mobile_process, "DUMB Mobile");
AUTOSTART_PROCESSES(&mobile_process);

PROCESS_THREAD(mobile_process, ev, data)
{
    PROCESS_BEGIN();

    simple_udp_register(&udp, DUMB_UDP_PORT, NULL,
                        DUMB_UDP_PORT, udp_rx_cb);
    serial_line_init();
    uart1_set_input(serial_line_input_byte);

    node_id8  = linkaddr_node_addr.u8[7];
    origin_id = (uint32_t)node_id8;
    random_init(origin_id);

    dumb_dedup_init(&dedup);
    dumb_carry_init(&carry);

#if DUMB_DIAG
    printf("STAT carry_slot_bytes=%u carry_items=%u carry_total_bytes=%lu\n",
           (unsigned)sizeof(dumb_carry_slot_t),
           (unsigned)DUMB_CARRY_MAX_ITEMS,
           (unsigned long)(sizeof(dumb_carry_slot_t) *
                           (unsigned long)DUMB_CARRY_MAX_ITEMS));
#endif

    etimer_set(&t_query,    DUMB_T_QUERY_MS    * CLOCK_SECOND / 1000);
    etimer_set(&t_gossip,   DUMB_T_GOSSIP_MS   * CLOCK_SECOND / 1000);
    etimer_set(&t_rsu_data, DUMB_T_DATA_MS     * CLOCK_SECOND / 1000);
    etimer_set(&t_loc,      DUMB_T_LOCATION_MS * CLOCK_SECOND / 1000);

    while(1) {
        PROCESS_YIELD();

        if(ev == serial_line_event_message && data)
            (void)parse_loc_line((const char *)data);

        if(etimer_expired(&t_loc)) {
            uart1_puts_ln("REQ_LOC");
            etimer_restart(&t_loc);
        }

        if(etimer_expired(&t_query)) {
            probe_epoch++;
            send_query();
            if(have_rsu) {
                uint32_t delta = probe_epoch - ack_epoch_last;
                if(delta >= 3) {
                    have_rsu = 0;
                    ctimer_stop(&uctx.timer); uctx.remaining = 0;
#if DUMB_DIAG
                    printf("%lu,STAT,HAVE_RSU=0\n",
                           (unsigned long)clock_seconds());
#endif
                }
            }
            etimer_restart(&t_query);
        }

        if(have_rsu && carry_has_pending()) start_carry_flush();

        if(have_rsu && have_loc && etimer_expired(&t_rsu_data)) {
            uint32_t msg_id = dumb_make_msgid(&seq16);
            printf("CREATE origin=%lu msg=%lu time=%lu main\n",
                   (unsigned long)origin_id,
                   (unsigned long)msg_id,
                   (unsigned long)last_ts_ms);
            send_data_unicast_to_rsu(msg_id);
            etimer_restart(&t_rsu_data);
        }

        if(!have_rsu && etimer_expired(&t_gossip) && !dctx.active) {
            start_gossip_data();
            etimer_restart(&t_gossip);
        }
    }

    PROCESS_END();
}

