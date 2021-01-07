"`#include <netinet/tcp.h>`"
from rsyscall._raw import ffi, lib # type: ignore
import enum

__all__ = [
    'TCP',
]

class TCP(enum.IntEnum):
    "User-settable options (used with setsockopt)"
    NODELAY = lib.TCP_NODELAY                           # Don't delay send to coalesce packets
    MAXSEG = lib.TCP_MAXSEG                             # Set maximum segment size
    CORK = lib.TCP_CORK                                 # Control sending of partial frames
    KEEPIDLE = lib.TCP_KEEPIDLE                         # Start keeplives after this period
    KEEPINTVL = lib.TCP_KEEPINTVL                       # Interval between keepalives
    KEEPCNT = lib.TCP_KEEPCNT                           # Number of keepalives before death
    SYNCNT = lib.TCP_SYNCNT                             # Number of SYN retransmits
    LINGER2 = lib.TCP_LINGER2                           # Life time of orphaned FIN-WAIT-2 state
    DEFER_ACCEPT = lib.TCP_DEFER_ACCEPT                 # Wake up listener only when data arrive
    WINDOW_CLAMP = lib.TCP_WINDOW_CLAMP                 # Bound advertised window
    INFO = lib.TCP_INFO                                 # Information about this connection.
    QUICKACK = lib.TCP_QUICKACK                         # Bock/reenable quick ACKs.
    CONGESTION = lib.TCP_CONGESTION                     # Congestion control algorithm.
    MD5SIG = lib.TCP_MD5SIG                             # TCP MD5 Signature (RFC2385)
    COOKIE_TRANSACTIONS = lib.TCP_COOKIE_TRANSACTIONS   # TCP Cookie Transactions
    THIN_LINEAR_TIMEOUTS = lib.TCP_THIN_LINEAR_TIMEOUTS # Use linear timeouts for thin streams
    THIN_DUPACK = lib.TCP_THIN_DUPACK                   # Fast retrans. after 1 dupack
    USER_TIMEOUT = lib.TCP_USER_TIMEOUT                 # How long for loss retry before timeout
    REPAIR = lib.TCP_REPAIR                             # TCP sock is under repair right now
    REPAIR_QUEUE = lib.TCP_REPAIR_QUEUE                 # Set TCP queue to repair
    QUEUE_SEQ = lib.TCP_QUEUE_SEQ                       # Set sequence number of repaired queue.
    REPAIR_OPTIONS = lib.TCP_REPAIR_OPTIONS             # Repair TCP connection options
    FASTOPEN = lib.TCP_FASTOPEN                         # Enable FastOpen on listeners
    TIMESTAMP = lib.TCP_TIMESTAMP                       # TCP time stamp
    NOTSENT_LOWAT = lib.TCP_NOTSENT_LOWAT               # Limit number of unsent bytes in write queue.
    CC_INFO = lib.TCP_CC_INFO                           # Get Congestion Control (optional) info.
    SAVE_SYN = lib.TCP_SAVE_SYN                         # Record SYN headers for new connections.
    SAVED_SYN = lib.TCP_SAVED_SYN                       # Get SYN headers recorded for connection.
    REPAIR_WINDOW = lib.TCP_REPAIR_WINDOW               # Get/set window parameters.
    FASTOPEN_CONNECT = lib.TCP_FASTOPEN_CONNECT         # Attempt FastOpen with connect.
    ULP = lib.TCP_ULP                                   # Attach a ULP to a TCP connection.
    MD5SIG_EXT = lib.TCP_MD5SIG_EXT                     # TCP MD5 Signature with extensions.
    FASTOPEN_KEY = lib.TCP_FASTOPEN_KEY                 # Set the key for Fast Open (cookie).
    FASTOPEN_NO_COOKIE = lib.TCP_FASTOPEN_NO_COOKIE     # Enable TFO without a TFO cookie.
    ZEROCOPY_RECEIVE = lib.TCP_ZEROCOPY_RECEIVE         # Perform a zerocopy receive
    INQ = lib.TCP_INQ                                   # Notify bytes available to read as a cmsg on read.
    CM_INQ = lib.TCP_CM_INQ                             # CMSG type for bytes available
    TX_DELAY = lib.TCP_TX_DELAY                         # Delay outgoing packets by XX usec.
