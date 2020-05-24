//
// Function: usage
//
// Description:
//    Print usage information
//
void usage(char *progname) 
{
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
int set_ttl(SOCKET s, int nTimeToLive) 
{
	int nRet;

	nRet = setsockopt(s, IPPROTO_IP, IP_TTL, (LPSTR) &nTimeToLive, sizeof(int));

	if (nRet == SOCKET_ERROR) 
	{
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
int decode_resp(char *buf, int bytes, SOCKADDR_IN *from, int ttl) 
{
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
USHORT checksum(USHORT *buffer, int size) 
{
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

void fill_icmp_data(char *icmp_data, int datasize) 
{
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

int createSocket(char * ip)
{
	//
	// Create a raw socket that will be used to send the ICMP
	// packets to the remote host you want to ping
	//
	sockRaw = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (sockRaw == INVALID_SOCKET) 
	{
		printf("WSASocket() failed: %d\n", WSAGetLastError());
		ExitProcess(-1);
	}
	//
	// Set the receive and send timeout values to a second
	//

	ret = setsockopt(sockRaw, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout));
	if (ret == SOCKET_ERROR) 
	{
		printf("setsockopt(SO_RCVTIMEO) failed: %d\n",
					WSAGetLastError());
		return -1;
	}

	ret = setsockopt(sockRaw, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout));
	if (ret == SOCKET_ERROR) 
	{
		printf("setsockopt(SO_SNDTIMEO) failed: %d\n",
					WSAGetLastError());
		return -1;
	}

	ZeroMemory(&dest, sizeof(dest));
	//
	// We need to resolve the host's ip address.  We check to see
	// if it is an actual Internet name versus an dotted decimal
	// IP address string.
	//
	dest.sin_family = AF_INET;
	if ((dest.sin_addr.s_addr = inet_addr(ip)) == INADDR_NONE) 
	{
		hp = gethostbyname(ip);
		if (hp)
			memcpy(&(dest.sin_addr), hp->h_addr, hp->h_length);
		else 
		{
			printf("Unable to resolve %s\n", ip);
			ExitProcess(-1);
		}
	}
	//
	// Set the data size to the default packet size.
	// We don't care about the data since this is just traceroute/ping
	//
	datasize = DEF_PACKET_SIZE;

	datasize += sizeof(IcmpHeader);
	//
	// Allocate the sending and receiving buffers for ICMP packets
	//
	icmp_data = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PACKET);
	recvbuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PACKET);

	if ((!icmp_data) || (!recvbuf)) 
	{
		printf("HeapAlloc() failed %d\n", GetLastError());
		return -1;
	}
	// Set the socket to bypass the standard routing mechanisms
	//  i.e. use the local protocol stack to the appropriate network
	//       interface
	//
	bOpt = TRUE;
	if (setsockopt(sockRaw, SOL_SOCKET, SO_DONTROUTE, (char *) &bOpt, sizeof(BOOL)) == SOCKET_ERROR)
		printf("setsockopt(SO_DONTROUTE) failed: %d\n", WSAGetLastError());

	//
	// Here we are creating and filling in an ICMP header that is the
	// core of trace route.
	//
	memset(icmp_data, 0, MAX_PACKET);
	fill_icmp_data(icmp_data, datasize);

	printf("\nTracing route to %s over a maximum of %d hops:\n\n", ip, maxhops);

	return 2;
}
