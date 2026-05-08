#ifndef BGKP_COMMON_H_
#define BGKP_COMMON_H_
/*
 * BGKP common definitions (roles, message types, flags, tuning).
 * - Network byte order on the wire is Big-Endian (BE).
 * - This header contains *only* constants shared across modules.
 *
 * Radio / PHY references (for choosing sensible defaults):
 * - IEEE 802.15.4 @ 2.4 GHz = 250 kbps (TI CC2420).
 * - TelosB / Tmote Sky typical range ~125 m outdoor.
 */
 
/* ===== Roles (3-char marker in the header) ===== */
#define BGKP_MARK_MOBILE "Mbl" /* Mobile mote */
#define BGKP_MARK_RSU    "RSU" /* Road Side Unit */

/* ===== Message types (BGKP v1.4) ===== */
#define BGKP_MSG_QUERY     0
#define BGKP_MSG_ACK       1
#define BGKP_MSG_DATA      2
#define BGKP_MSG_EMERGENCY 4

/* ===== Emergency flags (EF) ===== */
#define BGKP_EF_NONE   0   /* no emergency */
#define BGKP_EF_BRAKE  1   /* sudden braking / crash (M2M-critical) */
#define BGKP_EF_OIL    2   /* oil temperature emergency (for RSU) */
#define BGKP_EF_BATT   3   /* battery emergency (for RSU) */
#define BGKP_EF_FINISH 255 /* finish / clear emergency (creator only) */

/* ===== UDP port ===== */
#define BGKP_UDP_PORT 8765

/* ===== Broadcast TargetID ===== */
#define BGKP_TGT_BROADCAST 0xFFFFFFFFu

/* ===== Frame sizes ===== */
#ifndef BGKP_MAX_FRAME
#define BGKP_MAX_FRAME 64  /* safe upper bound for app payloads */
#endif

/* ===== Discovery / health-check ===== */
#define BGKP_T_QUERY_MS 2000 /* default Query period (ms) */

/* ===== Periodic DATA to RSU (ms) ===== */
#define BGKP_T_DATA_MS 1000

/* ===== Periodic Location Request ===== */
#define BGKP_T_LOCATION_MS 1000

/* ===== Gossip / Avalanche retransmission (broadcast)
 * Fan-out = how many times each node will rebroadcast a NEW frame
 * (with small jitter) to improve reachability. Dedup ensures one
 * fan-out cycle per (OriginID,MsgID).
 */
#define BGKP_T_GOSSIP_MS 2500 /* DATA broadcast period w/o RSU */
#define BGKP_FANOUT_DATA 3    /* #rebroadcasts per node for DATA */
#define BGKP_FANOUT_EF   3    /* #rebroadcasts per node for EF/Finish */
#define BGKP_JITTER_MS   100  /* Maximum time to wait for a new friend's ACK due to Jitter */
#define BGKP_DEDUP_MAX   64   /* Maximum message unique numbers to be deduplicated */

/* ===== Unicast reliability ===== */
#ifndef BGKP_UNICAST_RETRIES
#define BGKP_UNICAST_RETRIES 3 /* total sends per DATA (1+retries) */
#endif

/* ===== Friend-based gossip reliability ===== */
#ifndef BGKP_FRIEND_RETRIES
#define BGKP_FRIEND_RETRIES 3 /* total sends per DATA to a friend */
#endif

/* ===== Friend list empty value (u32) ===== */
#define BGKP_FRIEND_EMPTY 0xFFFFFFFFu

/* ===== Friend selection thresholds ===== */
// #define BGKP_FRIEND_DIST_DM 500 /* 50 m (500 dm) */
#define BGKP_FRIEND_DV_DMPS 150  /* 5 m/s (50 dm/s) */
#define BGKP_FRIEND_DIR_TOL 1   /* +/- 1 octant */

/* ===== Carry store sizing ===== */
#ifndef BGKP_CARRY_MAX_ITEMS
#define BGKP_CARRY_MAX_ITEMS 16 /* mobile's carry store count-limited */
#endif

/* ===== Direction (octants) for EF payload
 * Encoded as 1 byte 0..7: {N, NE, E, SE, S, SW, W, NW}.
 */
#define BGKP_DIR_E   0
#define BGKP_DIR_NE  1
#define BGKP_DIR_N   2
#define BGKP_DIR_NW  3
#define BGKP_DIR_W   4
#define BGKP_DIR_SW  5
#define BGKP_DIR_S   6
#define BGKP_DIR_SE  7
#define BGKP_DIR_UNK 255 /* unknown / not moving */


/* ===== DATA gossip TTL (hop budget) ===== */
#ifndef BGKP_DATA_TTL_DEFAULT
#define BGKP_DATA_TTL_DEFAULT 3 /* default hop budget for DATA */
#endif
#endif /* BGKP_COMMON_H_ */
