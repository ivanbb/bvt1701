//
// Function: usage
//
// Description:
//    Print usage information
//
void usage(char *progname) {
   printf("usage: %s host-name [max-hops]\n", progname);
   ExitProcess(-1);
}

//
// Function: set_ttl
//
// Description:
//    Set the time to live parameter on the socket. This controls
//    how far the packet will be forwared before a "timeout"
//    response will be sent back to us. This way we can see all
//    the hops along the way to the destination.
//
int set_ttl(SOCKET s, int nTimeToLive) {
   int nRet;

   nRet = setsockopt(s, IPPROTO_IP, IP_TTL, (LPSTR) &nTimeToLive, sizeof(int));

   if (nRet == SOCKET_ERROR) {
       printf("setsockopt(IP_TTL) failed: %d\n", WSAGetLastError());
       return 0;
   }
   return 1;
}

//
// Function: decode_resp
//
// Description:
//    The response is an IP packet. We must decode the IP header
//    to locate the ICMP data.
//
int decode_resp(char *buf, int bytes, SOCKADDR_IN *from, int ttl) {
   return 0;
}

//
// Function: checksum
//
// Description:
//    This function calculates the checksum for the ICMP header
//    which is a necessary field since we are building packets by
//    hand. Normally, the TCP layer handles all this when you do
//    sockets, but ICMP is at a somewhat lower level.
//
USHORT checksum(USHORT *buffer, int size) {
   unsigned long cksum = 0;

   while (size > 1) {
       cksum += *buffer++;
       size -= sizeof(USHORT);
   }
   if (size)
       cksum += *(UCHAR *) buffer;
   cksum = (cksum >> 16) + (cksum & 0xffff);
   cksum += (cksum >> 16);

   return (USHORT) (~cksum);
}

void fill_icmp_data(char *icmp_data, int datasize) {
   IcmpHeader *icmp_hdr;
   char *datapart;

   icmp_hdr = (IcmpHeader *) icmp_data;

   icmp_hdr->i_type = ICMP_ECHO;
   icmp_hdr->i_code = 0;
   icmp_hdr->i_id = (USHORT) GetCurrentProcessId();
   icmp_hdr->i_cksum = 0;
   icmp_hdr->i_seq = 0;

   datapart = icmp_data + sizeof(IcmpHeader);
   //
   // Place some junk in the buffer. Don't care about the data...
   //
   memset(datapart, 'E', datasize - sizeof(IcmpHeader));
}



