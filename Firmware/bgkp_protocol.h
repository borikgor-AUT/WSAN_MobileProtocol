#ifndef BGKP_PROTOCOL_H_
#define BGKP_PROTOCOL_H_

/*
 * BGKP protocol (v1.4-compatible) + compact inline utilities.
 * This header intentionally *replaces* the old bgkp_helpers.h to
 * avoid duplication and ODR issues. Do not include bgkp_helpers.h.
 * [802.15.4 MAC hdr]
 * [6LoWPAN hdr: Dispatch/IPHC/... (variable)]
 * [IPv6 hdr (compressed by IPHC, variable)]
 * [UDP hdr (compressed by NHC, variable, includes UDP checksum 2B)]
 * [UDP payload = BGKP frame]
 *     ["BGKP"(4)]
 *     [MsgLen(3)]
 *     [Marker(3) = "Mbl" or "RSU"]
 *     [SenderID(4) BE]
 *     [MsgType(1)]
 *     [MsgID(4) BE]
 *     [TargetID(4) BE]
 *     [OriginID(4) BE]
 *     [BGKP payload (variable)]
 *     [TimeStamp(4) BE]
 *     [BGKP Chk8(1)]
 * [802.15.4 FCS footer]
 **************************************
 * QUERY payload (MsgType = 0)  5 byte:
 *      [ef_flag (1)][ef_origin_id (4)]
 *
 * DATA payload (MsgType = 2) 17 byte:
 *      [x_dm (2)][y_dm (2)][v_dmps (2)][dir8 (1)][rssi_dbm (1)][friend1_be (4)][friend2_be (4)][ttl8 (1)]
 *
 * ACK  payload (MsgType = 1) 14 byte:
 *      [acked_type (1)][acked_origin (4)][acked_msg (4)][ef_code (1)][ef_origin (4)]
 *
 * Emergency payload (MsgType = 4) 12 byte:
 *      ['E''F''B''R' (4)][ef_code (1)][x_dm (2)][y_dm (2)][v_dmps (2)][dir8 (1)]
 *
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "contiki.h"
#include "random.h"
#include "sys/clock.h"
#include "net/ipv6/simple-udp.h"

#include "bgkp_common.h"

/* ------------------------------------------------------------------ */
/*  Checksum (Chk8)                                                    */
/* ------------------------------------------------------------------ */
/*
 * bgkp_chk8()
 * What:     Compute LSB of sum of bytes in buffer.
 * Methods:  Linear pass, uint16 accumulator, LSB at the end.
 * Creates:  local uint16_t 's' accumulator.
 */
static inline uint8_t bgkp_chk8(const uint8_t *buf, size_t len)
{
    uint16_t s = 0;
    for(size_t i = 0; i < len; ++i) s += buf[i];
    return (uint8_t)(s & 0xFF);
}

/* ------------------------------------------------------------------ */
/*  BE read/write (u32)                                                */
/* ------------------------------------------------------------------ */
/*
 * bgkp_u32_be_write()
 * What:     Store 32-bit value in Big-Endian order into p[0..3].
 * Methods:  Shift-and-mask.
 * Creates:  none.
 */
static inline void bgkp_u32_be_write(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xFF);
    p[1] = (uint8_t)((v >> 16) & 0xFF);
    p[2] = (uint8_t)((v >> 8)  & 0xFF);
    p[3] = (uint8_t)((v)       & 0xFF);
}

/*
 * bgkp_u32_be_read()
 * What:     Read Big-Endian 32-bit value from p[0..3].
 * Methods:  Shift-and-or.
 * Creates:  none.
 */
static inline uint32_t bgkp_u32_be_read(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | ((uint32_t)p[3]);
}



/* ------------------------------------------------------------------ */
/*  Random jitter (0..BGKP_JITTER_MS)                                  */
/* ------------------------------------------------------------------ */
/*
 * bgkp_rand_jitter_ms()
 * What:     Produce 0..BGKP_JITTER_MS pseudo-random jitter in ms.
 * Methods:  Scale 16-bit random_rand() to [0..JITTER].
 * Creates:  none.
 */
static inline uint16_t bgkp_rand_jitter_ms(void)
{
    unsigned int d_ms = 0;
    d_ms = (uint16_t)(((uint32_t)(random_rand() & 0xFFFFu) *
                       (uint32_t)BGKP_JITTER_MS) / 65535u);
#if FRIEND_LIST_MONITOR_ENABLED
    printf("MBL: Delaying %lu milliseconds.\n",(unsigned long)d_ms);
#endif //FRIEND_LIST_MONITOR_ENABLED
    return d_ms;
}

/* ------------------------------------------------------------------ */
/*  Direction quantization (octants)                                   */
/* ------------------------------------------------------------------ */
/*
 * bgkp_dir_from_delta()
 * What:     Map dx,dy (dm or any linear unit) to octant 0..7 or UNK.
 * Methods:  No floats/atan2; compare |dx| and |dy| with factor 2.
 * Creates:  local adx, ady, qx, qy.
 */
static inline uint8_t bgkp_dir_from_delta(int32_t dx, int32_t dy)
{
    /*
     * bgkp_dir_from_delta()
     * What:    Map dx,dy to octant 0..7; return BGKP_DIR_UNK when stationary.
     * Methods: No floats/atan2; compare |dx| and |dy| using factor 2.
     * Creates: adx, ady.
     */
    int32_t adx = (dx < 0) ? -dx : dx;
    int32_t ady = (dy < 0) ? -dy : dy;

    if (adx == 0 && ady == 0) return BGKP_DIR_UNK;

    if (adx >= (ady << 1)) return (dx >= 0) ? BGKP_DIR_E : BGKP_DIR_W;
    if (ady >= (adx << 1)) return (dy >= 0) ? BGKP_DIR_N : BGKP_DIR_S;

    if (dx >= 0 && dy >= 0) return BGKP_DIR_NE;
    if (dx <  0 && dy >= 0) return BGKP_DIR_NW;
    if (dx <  0 && dy <  0) return BGKP_DIR_SW;
    return BGKP_DIR_SE;
}

/* ------------------------------------------------------------------ */
/*  Dedup (very small fixed-size ring)                                 */
/* ------------------------------------------------------------------ */
#ifndef BGKP_DEDUP_MAX
#define BGKP_DEDUP_MAX 64
#endif

typedef struct {
    uint32_t origin_id;
    uint32_t msg_id;
} bgkp_key_t;

typedef struct {
    bgkp_key_t items[BGKP_DEDUP_MAX];
    uint8_t    used;
    uint8_t    head; /* ring index for overwrite */
} bgkp_dedup_t;

/*
 * bgkp_dedup_init()
 * What:     Reset dedup ring.
 * Methods:  memset.
 * Creates:  none.
 */
static inline void bgkp_dedup_init(bgkp_dedup_t *d)
{
    memset(d, 0, sizeof(*d));
}

/*
 * bgkp_dedup_has()
 * What:     Check if (origin,msg) exists in ring.
 * Methods:  linear scan up to 'used'.
 * Creates:  loop index idx.
 */
static inline uint8_t bgkp_dedup_has(bgkp_dedup_t *d,
                                     uint32_t origin,
                                     uint32_t msg)
{
    for(uint8_t i = 0; i < d->used; ++i) {
        uint8_t idx = (uint8_t)((i < BGKP_DEDUP_MAX) ? i
                                                    : (i % BGKP_DEDUP_MAX));
        if(d->items[idx].origin_id == origin &&
           d->items[idx].msg_id    == msg) return 1;
    }
    return 0;
}

/*
 * bgkp_dedup_put()
 * What:     Insert (origin,msg) at head, overwrite when full.
 * Methods:  ring buffer with head++ mod size.
 * Creates:  none.
 */
static inline void bgkp_dedup_put(bgkp_dedup_t *d,
                                  uint32_t origin,
                                  uint32_t msg)
{
    d->items[d->head].origin_id = origin;
    d->items[d->head].msg_id    = msg;
    d->head = (uint8_t)((d->head + 1) % BGKP_DEDUP_MAX);
    if(d->used < BGKP_DEDUP_MAX) d->used++;
}

/* ------------------------------------------------------------------ */
/*  Carry store (Mobile) — compact record format                      */
/*                                                                    */
/*  Instead of storing a full serialized wire frame (49 bytes for     */
/*  DATA, 44 for EF), we store only the fields needed by the RSU.     */
/*  The BGKP frame is rebuilt from this record at flush time.         */
/*                                                                    */
/*  Record layout (21 bytes):                                         */
/*    msg_type  (1)  — BGKP_MSG_DATA or BGKP_MSG_EMERGENCY            */
/*    origin_id (4)  — creator of the message                         */
/*    msg_id    (4)  — message identifier                             */
/*    ts_ms     (4)  — creation timestamp (frozen)                    */
/*    x_dm      (2)  — position X, dm, little-endian                  */
/*    y_dm      (2)  — position Y, dm, little-endian                  */
/*    v_dmps    (2)  — speed, dm/s, little-endian                     */
/*    dir8      (1)  — direction octant 0..7 or BGKP_DIR_UNK          */
/*    rssi_dbm  (1)  — RSSI (0 in Cooja)                              */
/*    ttl8      (1)  — DATA hop budget                                */
/*    ef_code   (1)  — EF code for EMERGENCY; 0 for DATA              */
/*                                                                    */
/*  Total: 21 bytes per slot × 16 slots = 336 bytes                   */
/*  (vs 49 × 16 = 784 bytes for full-frame storage, which also        */
/*   caused memory corruption when BGKP_CARRY_MAX_FRAME was 16)       */
/* ------------------------------------------------------------------ */
typedef struct {
    uint8_t  msg_type;      /* BGKP_MSG_DATA or BGKP_MSG_EMERGENCY */
    uint32_t origin_id;
    uint32_t msg_id;
    uint32_t ts_ms;
    int16_t  x_dm;
    int16_t  y_dm;
    uint16_t v_dmps;
    uint8_t  dir8;
    int8_t   rssi_dbm;
    uint8_t  ttl8;          /* DATA hop budget */
    uint8_t  ef_code;       /* 0 for DATA records */
    uint8_t  in_use;        /* 1 if slot is occupied; 0 = free/acked */
} __attribute__((packed)) bgkp_carry_slot_t;

/* Compile-time sanity check (requires C11).
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
_Static_assert(sizeof(bgkp_carry_slot_t) == 23,
               "bgkp_carry_slot_t size changed: check packing/layout");
#endif
*/

typedef struct {
    bgkp_carry_slot_t slots[BGKP_CARRY_MAX_ITEMS];
    uint16_t          count;
    uint16_t          head;  /* next write index (ring) */
} bgkp_carry_t;

/*
 * bgkp_carry_init()
 * What:     Reset carry store.
 * Methods:  memset.
 * Creates:  none.
 */
static inline void bgkp_carry_init(bgkp_carry_t *c)
{
    memset(c, 0, sizeof(*c));
}

/*
 * bgkp_carry_exists()
 * What:     Check if (origin, msg) is already in the store.
 * Methods:  Linear scan over in_use slots.
 * Creates:  loop index i.
 */
static inline uint8_t bgkp_carry_exists(bgkp_carry_t *c,
                                        uint32_t origin,
                                        uint32_t msg)
{
    for(uint16_t i = 0; i < BGKP_CARRY_MAX_ITEMS; ++i) {
        if(c->slots[i].in_use &&
           c->slots[i].origin_id == origin &&
           c->slots[i].msg_id    == msg) return 1;
    }
    return 0;
}

/*
 * bgkp_carry_put()
 * What:     Insert a compact record into the ring store.
 *           Overwrites the oldest slot when full (ring semantics).
 * Methods:  Write fields at head; advance head mod BGKP_CARRY_MAX_ITEMS.
 * Creates:  none.
 */
static inline void bgkp_carry_put(bgkp_carry_t *c,
                                  uint8_t  msg_type,
                                  uint32_t origin,
                                  uint32_t msg,
                                  uint32_t ts_ms,
                                  int16_t  x_dm,
                                  int16_t  y_dm,
                                  uint16_t v_dmps,
                                  uint8_t  dir8,
                                  int8_t   rssi_dbm,
                                  uint8_t  ttl8,
                                  uint8_t  ef_code)
{
    uint16_t idx = 0xFFFFu;

    /* Find a free slot first (in_use == 0). */
    for(uint16_t i = 0; i < BGKP_CARRY_MAX_ITEMS; ++i) {
        if(!c->slots[i].in_use) { idx = i; break; }
    }

    /* If no free slot exists, fall back to head (forced overwrite). */
    uint8_t was_free = 0;
    if(idx == 0xFFFFu) {
        idx = c->head;
        was_free = (c->slots[idx].in_use == 0) ? 1 : 0;
    } else {
        was_free = 1;
    }

    c->slots[idx].in_use    = 1;
    c->slots[idx].msg_type  = msg_type;
    c->slots[idx].origin_id = origin;
    c->slots[idx].msg_id    = msg;
    c->slots[idx].ts_ms     = ts_ms;
    c->slots[idx].x_dm      = x_dm;
    c->slots[idx].y_dm      = y_dm;
    c->slots[idx].v_dmps    = v_dmps;
    c->slots[idx].dir8      = dir8;
    c->slots[idx].rssi_dbm  = rssi_dbm;
    c->slots[idx].ttl8      = ttl8;
    c->slots[idx].ef_code   = ef_code;

    /* Move head to the next slot after the one we just used. */
    c->head = (uint16_t)((idx + 1u) % BGKP_CARRY_MAX_ITEMS);

    /* Count increases only when we consumed a previously free slot. */
    if(was_free && c->count < BGKP_CARRY_MAX_ITEMS) c->count++;
}

/*
 * bgkp_carry_ack()
 * What:     Mark a slot as free when the RSU ACKs it.
 * Methods:  Linear scan; clear in_use on match.
 * Creates:  loop index i.
 */
static inline void bgkp_carry_ack(bgkp_carry_t *c,
                                  uint32_t origin,
                                  uint32_t msg)
{
    for(uint16_t i = 0; i < BGKP_CARRY_MAX_ITEMS; ++i) {
        if(c->slots[i].in_use &&
           c->slots[i].origin_id == origin &&
           c->slots[i].msg_id    == msg) {
            c->slots[i].in_use = 0;
            if(c->count > 0) c->count--;
            return;
        }
    }
}

/* ------------------------------------------------------------------ */
/*  MsgID helper                                                       */
/* ------------------------------------------------------------------ */
/*
 * bgkp_make_msgid()
 * What:     Build MsgID = [HH][MM][SEQ16] (BE on the wire in pack()).
 * Methods:  Use clock_seconds(); reset seq if minute changed.
 * Creates:  static g_min_snapshot; local hh, mm, seq.
 */
static inline uint32_t bgkp_make_msgid(uint16_t *p_seq16)
{
    static uint8_t g_min_snapshot = 0;
    uint32_t secs = clock_seconds();
    uint8_t hh = (uint8_t)((secs / 3600) % 24);
    uint8_t mm = (uint8_t)((secs / 60) % 60);

    if(mm != g_min_snapshot) {
        g_min_snapshot = mm;
        *p_seq16 = 0;
    }

    uint16_t seq = (*p_seq16)++;
    return ((uint32_t)hh << 24) | ((uint32_t)mm << 16) | (uint32_t)seq;
}



/* ------------------------------------------------------------------ */
/*  BGKP wire format (pack/parse)                                      */
/* ------------------------------------------------------------------ */
/*
 * BGKP frame (v1.5) on the wire (BE multi-byte header fields):
 *   [ "BGKP"(4) ]
 *   [ MsgLen(3) ]        // [00][hi][lo], bytes from Marker .. CS inclusive
 *   [ Marker(3) ]        // "Mbl" or "RSU"
 *   [ SenderID(4) ]      // BE, changes every hop (physical sender)
 *   [ MsgType(1) ]
 *   [ MsgID(4) ]         // BE
 *   [ TargetID(4) ]      // BE (logical target, or broadcast)
 *   [ OriginID(4) ]      // BE (creator, stable)
 *   [ Payload(..) ]
 *   [ TimeStamp(4) ]     // BE (ms from simulator/script)
 *   [ CS(1) ]            // LSB of sum from 'W' to end of TimeStamp
 */

typedef struct {
    char marker[3];
    uint32_t sender_id;
    uint32_t origin_id;
    uint8_t msg_type;
    uint32_t msg_id;
    uint32_t target_id;
    uint16_t payload_len;
    const uint8_t *payload;
    uint32_t ts_ms;
} bgkp_fields_t;

/* =========================================================================
 * Unified BGKP payload descriptions
 * ========================================================================= */

/* DATA payload: metrics + friend list (always present) */
typedef struct {
    int16_t x_dm;            /* position X, decimeters (LE in memory) */
    int16_t y_dm;            /* position Y, decimeters (LE in memory) */
    uint16_t v_dmps;         /* speed, dm/s (LE in memory) */
    uint8_t dir8;            /* direction 0..7 */
    int8_t rssi_dbm;         /* RSSI placeholder (0 in Cooja) */
    uint8_t friend1_be[4];   /* friend slot #1, BE on wire */
    uint8_t friend2_be[4];   /* friend slot #2, BE on wire */
    uint8_t ttl8;            /* NEW: hop budget for DATA gossip */
} __attribute__((packed)) bgkp_data_payload_t;

/* EMERGENCY payload: EF code + same metrics */
typedef struct __attribute__((packed)) {
    char    sig[4];     /* "EFBR" */
    uint8_t ef_code;    /* BGKP_EF_* */
    int16_t x_dm;
    int16_t y_dm;
    uint16_t v_dmps;
    uint8_t dir8;
} bgkp_emergency_payload_t;

/*
 * bgkp_pack()
 * What:     Serialize fields into 'out'; return total len in out_len.
 * Methods:  Fill header, write BE fields, compute body len and CS.
 */
static inline uint8_t
bgkp_pack(const bgkp_fields_t *f, uint8_t *out, uint16_t cap, uint16_t *out_len)
{
    if(!f || !out || !out_len || cap < 32) return 0;

    /* "BGKP" */
    out[0] = 'W'; out[1] = 'S'; out[2] = 'A'; out[3] = 'N';

    /* MsgLen placeholder */
    out[4] = 0x00; out[5] = 0x00; out[6] = 0x00;

    /* Marker */
    out[7] = (uint8_t)f->marker[0];
    out[8] = (uint8_t)f->marker[1];
    out[9] = (uint8_t)f->marker[2];

    /* SenderID BE */
    bgkp_u32_be_write(&out[10], f->sender_id);

    /* MsgType */
    out[14] = f->msg_type;

    /* MsgID BE */
    bgkp_u32_be_write(&out[15], f->msg_id);

    /* TargetID BE */
    bgkp_u32_be_write(&out[19], f->target_id);

    /* OriginID BE */
    bgkp_u32_be_write(&out[23], f->origin_id);

    /* Payload */
    if(f->payload_len > (BGKP_MAX_FRAME - 32)) return 0;
    if(f->payload_len && f->payload) {
        memcpy(&out[27], f->payload, f->payload_len);
    }

    /* TimeStamp BE */
    bgkp_u32_be_write(&out[27 + f->payload_len], f->ts_ms);

    /* Body length (Marker..CS inclusive) */
    uint16_t body_len = (uint16_t)(25 + f->payload_len);

    /* Fill MsgLen hi/lo (out[4] always 0x00) */
    out[5] = (uint8_t)((body_len >> 8) & 0xFF);
    out[6] = (uint8_t)(body_len & 0xFF);

    /* CS over all bytes before CS */
    uint16_t pre_cs_len = (uint16_t)(4 + 3 + body_len - 1);
    uint8_t cs = bgkp_chk8(out, pre_cs_len);
    out[27 + f->payload_len + 4] = cs;

    *out_len = (uint16_t)(pre_cs_len + 1);
    return 1;
}

/*
 * bgkp_parse()
 * What:     Validate and parse BGKP frame from 'in'.
 * Methods:  Check signature/length/CS; expose payload view.
 */
static inline uint8_t
bgkp_parse(const uint8_t *in, uint16_t in_len,
           bgkp_fields_t *f, const uint8_t **pl, uint16_t *pl_len)
{
    if(!in || !f || !pl || !pl_len || in_len < 32) return 0;
    if(in[0] != 'W' || in[1] != 'S' || in[2] != 'A' || in[3] != 'N') return 0;

    uint16_t body_len = (uint16_t)(((uint16_t)in[5] << 8) | in[6]);
    uint16_t expect = (uint16_t)(4 + 3 + body_len);
    if(in_len != expect) return 0;

    uint8_t cs_calc = bgkp_chk8(in, (uint16_t)(expect - 1));
    uint8_t cs_got = in[expect - 1];
    if(cs_calc != cs_got) return 0;

    f->marker[0] = (char)in[7];
    f->marker[1] = (char)in[8];
    f->marker[2] = (char)in[9];

    f->sender_id = bgkp_u32_be_read(&in[10]);
    f->msg_type  = in[14];
    f->msg_id    = bgkp_u32_be_read(&in[15]);
    f->target_id = bgkp_u32_be_read(&in[19]);
    f->origin_id = bgkp_u32_be_read(&in[23]);

    uint16_t pay_len = (uint16_t)(body_len - 25);
    *pl = &in[27];
    *pl_len = pay_len;

    f->payload = *pl;
    f->payload_len = *pl_len;
    f->ts_ms = bgkp_u32_be_read(&in[27 + pay_len]);

    return 1;
}

#endif /* BGKP_PROTOCOL_H_ */
