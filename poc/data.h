/**
Defines all global data
**/
//
// Defines for ICMP message types
//
#define ICMP_ECHOREPLY      0
#define ICMP_DESTUNREACH    3
#define ICMP_SRCQUENCH      4
#define ICMP_REDIRECT       5
#define ICMP_ECHO           8
#define ICMP_TIMEOUT       11
#define ICMP_PARMERR       12

#define MAX_HOPS           30

#define ICMP_MIN 8    // Minimum 8 byte icmp packet (just header)

//
// IP Header
//
typedef struct iphdr {
   unsigned int h_len:4;        // Length of the header
   unsigned int version:4;      // Version of IP
   unsigned char tos;            // Type of service
   unsigned short total_len;      // Total length of the packet
   unsigned short ident;          // Unique identifier
   unsigned short frag_and_flags; // Flags
   unsigned char ttl;            // Time to live
   unsigned char proto;          // Protocol (TCP, UDP etc)
   unsigned short checksum;       // IP checksum
   unsigned int sourceIP;       // Source IP
   unsigned int destIP;         // Destination IP
} IpHeader;

//
// ICMP header
//
typedef struct _ihdr {
   BYTE i_type;               // ICMP message type
   BYTE i_code;               // Sub code
   USHORT i_cksum;
   USHORT i_id;                 // Unique id
   USHORT i_seq;                // Sequence number
   // This is not the std header, but we reserve space for time
   ULONG timestamp;
} IcmpHeader;

#define DEF_PACKET_SIZE         32
#define MAX_PACKET            1024

//
// Global variable
//
WSADATA wsd;
SOCKET sockRaw;
HOSTENT *hp = NULL;
SOCKADDR_IN dest,
                from;
int ret = 0,
       datasize = 0,
       fromlen = sizeof(from),
       done = 0,
       maxhops = 30,
       timeout = 1000;

char *icmp_data = "",
       *recvbuf = "";
       
BOOL bOpt = FALSE;
USHORT seq_no = 0;

FILE * fp; // Pointer to the log file

//
// Functions
//
int printLog(char* text_prihodit);
void finish();
