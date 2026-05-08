#ifndef DUMB_COMMON_H_
#define DUMB_COMMON_H_
/*
 * DUMB common definitions (roles, message types, flags, tuning).
 * - Network byte order on the wire is Big-Endian (BE).
 * - This header contains *only* constants shared across modules.
 *
 * Radio / PHY references (for choosing sensible defaults):
 * - IEEE 802.15.4 @ 2.4 GHz = 250 kbps (TI CC2420).
 * - TelosB / Tmote Sky typical range ~125 m outdoor.
 */
 
/* ===== Roles (3-char marker in the header) ===== */
#define DUMB_MARK_MOBILE "Mbl" /* Mobile mote */
#define DUMB_MARK_RSU    "RSU" /* Road Side Unit */

/* ===== Message types (DUMB v1.4) ===== */
#define DUMB_MSG_QUERY     0
#define DUMB_MSG_ACK       1
#define DUMB_MSG_DATA      2
#define DUMB_MSG_EMERGENCY 4

/* ===== Emergency flags (EF) ===== */
#define DUMB_EF_NONE   0   /* no emergency */
#define DUMB_EF_BRAKE  1   /* sudden braking / crash (M2M-critical) */
#define DUMB_EF_OIL    2   /* oil temperature emergency (for RSU) */
#define DUMB_EF_BATT   3   /* battery emergency (for RSU) */
#define DUMB_EF_FINISH 255 /* finish / clear emergency (creator only) */

/* ===== UDP port ===== */
#define DUMB_UDP_PORT 8765

/* ===== Broadcast TargetID ===== */
#define DUMB_TGT_BROADCAST 0xFFFFFFFFu

/* ===== Frame sizes ===== */
#ifndef DUMB_MAX_FRAME
#define DUMB_MAX_FRAME 64  /* safe upper bound for app payloads */
#endif

/* ===== Discovery / health-check ===== */
#define DUMB_T_QUERY_MS 2000 /* default Query period (ms) */

/* ===== Periodic DATA to RSU (ms) ===== */
#define DUMB_T_DATA_MS 1000

/* ===== Periodic Location Request ===== */
#define DUMB_T_LOCATION_MS 1000

/* ===== Gossip / Avalanche retransmission (broadcast)
 * Fan-out = how many times each node will rebroadcast a NEW frame
 * (with small jitter) to improve reachability. Dedup ensures one
 * fan-out cycle per (OriginID,MsgID).
 */
#define DUMB_T_GOSSIP_MS 2500 /* DATA broadcast period w/o RSU */
#define DUMB_FANOUT_DATA 0    /* #rebroadcasts per node for DATA */
#define DUMB_FANOUT_EF   0    /* #rebroadcasts per node for EF/Finish */
#define DUMB_JITTER_MS   100  /* Maximum time to wait for a new friend's ACK due to Jitter */
#define DUMB_DEDUP_MAX   64   /* Maximum message unique numbers to be deduplicated */

/* ===== Unicast reliability ===== */
#ifndef DUMB_UNICAST_RETRIES
#define DUMB_UNICAST_RETRIES 2 /* total sends per DATA (1+retries) */
#endif

/* ===== Friend-based gossip reliability ===== */
#ifndef DUMB_FRIEND_RETRIES
#define DUMB_FRIEND_RETRIES 0 /* total sends per DATA to a friend */
#endif

/* ===== Friend list empty value (u32) ===== */
#define DUMB_FRIEND_EMPTY 0xFFFFFFFFu

/* ===== Friend selection thresholds ===== */
// #define DUMB_FRIEND_DIST_DM 500 /* 50 m (500 dm) */
#define DUMB_FRIEND_DV_DMPS 150  /* 5 m/s (50 dm/s) */
#define DUMB_FRIEND_DIR_TOL 1   /* +/- 1 octant */

/* ===== Carry store sizing ===== */
#ifndef DUMB_CARRY_MAX_ITEMS
#define DUMB_CARRY_MAX_ITEMS 1  /* mobile's carry store count-limited */
#endif

/* ===== Direction (octants) for EF payload
 * Encoded as 1 byte 0..7: {N, NE, E, SE, S, SW, W, NW}.
 */
#define DUMB_DIR_E   0
#define DUMB_DIR_NE  1
#define DUMB_DIR_N   2
#define DUMB_DIR_NW  3
#define DUMB_DIR_W   4
#define DUMB_DIR_SW  5
#define DUMB_DIR_S   6
#define DUMB_DIR_SE  7
#define DUMB_DIR_UNK 255 /* unknown / not moving */


/* ===== DATA gossip TTL (hop budget) ===== */
#ifndef DUMB_DATA_TTL_DEFAULT
#define DUMB_DATA_TTL_DEFAULT 3 /* default hop budget for DATA */
#endif
#endif /* DUMB_COMMON_H_ */
