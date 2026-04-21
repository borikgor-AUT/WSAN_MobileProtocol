/* project-conf.h — minimal IPv6/UDP, no RPL/TSCH/LLSEC, small buffers */

/* --- Core netstack selections & features --- */
#define UIP_CONF_TCP                0     /* no TCP */
#define NETSTACK_CONF_WITH_RPL      0     /* no RPL */
#define LLSEC802154_CONF_ENABLED    0     /* no link-layer security */
#define SICSLOWPAN_CONF_FRAG        0     /* no 6LoWPAN fragmentation */

/* Reduce queues / buffers / tables (RAM savers) */
#define QUEUEBUF_CONF_NUM           8
#define UIP_CONF_BUFFER_SIZE        240
#define NBR_TABLE_CONF_MAX_NEIGHBORS 8
#define UIP_CONF_MAX_ROUTES         0
#define UIP_CONF_ROUTER             0

/* Logging off (saves ROM/rodata) */
#define LOG_CONF_ENABLED            0