#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#pragma pack(4)

#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>

#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")
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

//���� ���� ������ ���� � �����, ��� ��� ������� � ��� ��������� ������ ���������, �������� ���������
//��������
WSADATA wsd;
SOCKET sockRaw;
HOSTENT *hp = NULL;
SOCKADDR_IN dest,
       from;
int ret,
       datasize,
       fromlen = sizeof(from),
       done = 0,
       maxhops,
       timeout = 10000;

char *icmp_data,
       *recvbuf;
BOOL bOpt;
USHORT seq_no = 0;

FILE *log; // ��������� �� log ����


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


int start(char *log) {
   FILE *fp = fopen(log, "a+");
   char time_str[128] = "";
   int i = 0;
   int j = 0;
   char info[100] = "     Status: start log ... \r"; //������ � ���������
   if (fp != NULL)
   {
       time_t time_now = time(NULL);
       struct tm *newtime;
       newtime = localtime(&time_now);
       for (i; i < strlen(time_str); i++) {
           /* ���������� ����� � ��� ��������� ������� fputc() */
           fputc(time_str[i], fp);
       }
       for (j; j < strlen(info); j++) {
           /* ���������� ��������� � ��� ��������� ������� fputc() */
           fputc(info[j], fp);
       }
       return 1; //��������� ���������� 1 (������� ������� ���� � ���������� ������)
   } else return 0; //��������� ���������� 0 (�� ������� ������� ����)
}


/**
�������������� ������
@param ipAddress
@return int 1-�������� �� 0-��������
**/
int analyze(char *ipAddress) {
   int i = 0;
   int count_point = 0;
   for (i = 0; i < strlen(ipAddress); i++) //��������� ���� �� � ip ������� �� ���������� ������ ��� ������, ���� ���� �� ���������� 0
   {
       if (!((ipAddress[i] >= '0' && ipAddress[i] <= '9') || ipAddress[i] == '.'))
           return 0;
   }
   for (i = 0; i < strlen(ipAddress); i++) // ��������� ���-�� ����� � IP
   {
       if (ipAddress[i] == '.')
           count_point++;
   }
   if (count_point != 3)// ���� ������ 3 �� ���������� 0
       return 0;
   for (i = 0; i < strlen(ipAddress); i++)//��������� ����� IP
   {
       //string str = "";
       char str[10] = "";
       int p = 0;
       for (; ipAddress[i] != '.' && i < strlen(ipAddress); i++, p++) {// ��������� ����� IP
           str[p] = ipAddress[i];
       }
       str[p] = '\0';
       if (str[0] != '0') // ��������� �������� �� ������(�� �������� �� ����� � �0�)
       {
           int a = atoi(str);
           if (a > 255)// ���� ����� IP ������ 255, �� ���������� 0
               return 0;
       } else return 0; //���� ����� ���������� � 0 �� ���������� 0
   }
   return 1;// ���������� 1 ���� IP ��������� ������
}

int getReply(char *buf, int bytes, SOCKADDR_IN *from, int ttl) {
   IpHeader *iphdr = NULL;
   IcmpHeader *icmphdr = NULL;
   unsigned short iphdrlen;
   struct hostent *lpHostent = NULL;
   struct in_addr inaddr = from->sin_addr;

   iphdr = (IpHeader *) buf;
   // Number of 32-bit words * 4 = bytes
   iphdrlen = iphdr->h_len * 4;

   if (bytes < iphdrlen + ICMP_MIN)
       printf("Too few bytes from% s\n", inet_ntoa(from->sin_addr));


   icmphdr = (IcmpHeader *) (buf + iphdrlen);

   switch (icmphdr->i_type) {
       case ICMP_ECHOREPLY:     // Response from destination
           lpHostent = gethostbyaddr((const char *) &from->sin_addr, AF_INET, sizeof(struct in_addr));
           if (lpHostent != NULL)
               printf("%2d  %s (%s)\n", ttl, lpHostent->h_name,
                      inet_ntoa(inaddr));
           return 1;
           break;
       case ICMP_TIMEOUT:      // Response from router along the way
           printf("%2d  %s\n", ttl, inet_ntoa(inaddr));
           return 0;
           break;
       case ICMP_DESTUNREACH:  // Can't reach the destination at all
           printf("%2d  %s  reports: Host is unreachable\n", ttl,
                  inet_ntoa(inaddr));
           return 1;
           break;
       default:
           printf("non-echo type %d recvd\n", icmphdr->i_type);
           return 1;
           break;
   }

}

/**
�������� ����� �� ����
��� ��������� ����� ��� - ����������
@param ttl ����� ����� ������
@return int state (0 - ����� �������, 1 - ��������� �������� ����, 2 - ������ ���������)
**/
int receiveICMP(int ttl) {
// Read a packet back from the destination or a router along
   // the way.
   //
   ret = recvfrom(sockRaw, recvbuf, MAX_PACKET, 0, (struct sockaddr *) &from, &fromlen);
   if (ret == SOCKET_ERROR) {
       if (WSAGetLastError() == WSAETIMEDOUT) {
           printf("%2d  Receive Request timed out.\n", ttl);
       }
       printf("recvfrom() failed: %d\n", WSAGetLastError());
       return -1;
   }
   //
   // Decode the response to see if the ICMP response is from a
   // router along the way or whether it has reached the destination.
   //
   //  done = decode_resp(recvbuf, ret, &from, ttl);
   done = getReply(recvbuf, ret, &from, ttl);
   Sleep(100);

   return 0;
}

/**
�������� �������
��� ������ ��������� - ����������
��� ���� ip � ��� - ��
����� ip ����� ����� ��� ������ �� �����
@param char* ip ����� ��������� ����
@param int ttl ����� ����� ������ �� ������� ����
@param char* log �������� ���-�����
@return none
**/
int sendRequest(char *ip, int ttl, FILE *log) {
   //
   // Send the ICMP packet to the destination
   //
   int bwrote;
   bwrote = sendto(sockRaw, icmp_data, datasize, 0, (SOCKADDR *) &dest, sizeof(dest));
   if (bwrote == SOCKET_ERROR) {
       if (WSAGetLastError() == WSAETIMEDOUT) {
           printf("%2d  Send request timed out.\n", ttl);
       }
       printf("sendto() failed: %d\n", WSAGetLastError());
       return -1;
   }

}

/**
����� ����������� ������
��������� ����� � ���-����
@param log �������� ���-�����
@return none
**/
int finish(char *log) {
   FILE *fp = fopen(log, "r+"); //�������� ������������� �����
   char time_str[128] = ""; //������ ��� ���������� ���������������� �������
   int i = 0;
   char info[100] = "     Status: Close log ... \r"; //������ � ���������
   if (fp != NULL)// ���� ������� ������� ����
   {
       time_t time_now = time(NULL); //��������� ��������� �����
       struct tm *newtime;  //��������� �� ��������� � ��������� ��������
       newtime = localtime(&time_now); //����������� ��������� ����� � ���������
       strftime(time_str, 128, "Date:  %x %A %X", newtime); //����������� ��������� ����� � ��������� ������
       for (i = 0; i < strlen(time_str); i++) {
           /* ���������� ����� � ��� ��������� ������� fputc() */
           fputc(time_str[i], fp);
       }

       for (i = 0; i < strlen(info); i++) {
           /* ���������� ��������� � ��� ��������� ������� fputc() */
           fputc(info[i], fp);
       }
       fclose(fp);//��������� ����
       return 1; //��������� ���������� 1 (������� ������� ���� � ���������� ������)
   } else return 0; //��������� ���������� 0 (�� ������� ������� ����)
}

/**
����������� ����� ��������
��������� ������ ���������
������� ������ �������
@param code ��������� ��� ������
@param log �������� ���-�����
@return errorText ������ ������� ��� �����
**/
int codeOS(FILE *log, int code) {  //printf(������� ������ � ���, �������� ����������);
   char errStr1[] = "�������� ����� �����, ��� ������ - 1";
   char errStr2[] = "�� ��, ��� � ��� 3? � ��, ��� ������ - 2";
   char errStr3[] = "�� ���������� ��� �����(��������), ��� ������ - 3";
   switch (code) {
       case 1:
           fputs("�������� ����� �����, ��� ������ - 1", log);
           printf(errStr1);
           // fwrite(errStr);
           break;
       case 2:
           printf(errStr2);
           fputs("??", log);
           //fwrite(errStr);
           return 1;
       case 3:
           fputs("�� ���������� ��� �����(��������), ��� ������ - 3", log);
           printf(errStr3);
           // fwrite(errStr);
           break;
   }
   return 0;
}

/**
����� ������ ����������� �� �����
@param char *buf ����� � ��������� ������� ������
@param int bytes ���������� ����
@param SOCKADDR_IN *from ������ ���� �� �������� ������ ���������
@param int tll ����� ����� ���������� ������
**/



/**
������ � ��� ����
@param logMsg ��������� ��� ������
@return 1 - ������ ������� 0 - ������ ������
@throw ������ ������
**/
int Print_log(char *log, char *ip, int code, int TTL) {
   FILE *fp = fopen(log, "r+"); //�������� ������������� �����
   char time_str[128] = ""; //������ ��� ���������� ���������������� �������
   int i =0;
   char info_TTL[100] = "     TTL set value "; //������ TTL
   char info_1[100] = "     Status: Invalid IP address format \r"; //������ � ���������
   char str_TTL[10] = "";
   char end_r_TTL[] = "\r";
   const char end_r[] = "\r";
   char info_failed[100] = "     Status: Failed to connect \r"; //������ � ���������
   char info[100] = "     Status: Acknowledgment IP address "; //������ � ���������
   if (fp != NULL)// ���� ������� ������� ����
   {
       FILE *fp = fopen(log, "a+");//��������  ����� ��� ���������� ������
       time_t time_now = time(NULL); //��������� ��������� �����
       struct tm *newtime;  //��������� �� ��������� � ��������� ��������
       newtime = localtime(&time_now); //����������� ��������� ����� � ���������
       strftime(time_str, 128, "Date:  %x %A %X", newtime); //����������� ��������� ����� � ��������� ������
       for (i = 0; i < strlen(time_str); i++) {
           /* ���������� ����� � ��� ��������� ������� fputc() */
           fputc(time_str[i], fp);
       }
       switch (code) {
           case 1: //���� IP ����� ����� �������� ������
           
               for (i = 0; i < strlen(info); i++) {
                   /* ���������� ��������� � ��� ��������� ������� fputc() */
                   fputc(info_1[i], fp);
               }
               return 1; //��������� ���������� 1 (������� ������� ���� � ���������� ������)
           
               break;
           case 2: //�������� ����� �� �������������� IP(�� ��������� IP)
           
               itoa(TTL, str_TTL, 10);//TTL ����������� � char
               strcat(info_TTL, str_TTL); // �������� TTL � info
               strcat(info_TTL, end_r_TTL);// �������� ������� ������ � info
               for (i = 0; i < strlen(info_TTL); i++) {
                   /* ���������� �������� TTL � ��� ��������� ������� fputc() */
                   fputc(info_TTL[i], fp);
               }
               for (i = 0; i < strlen(time_str); i++) {
                   /* ���������� ����� � ��� ��������� ������� fputc() */
                   fputc(time_str[i], fp);
               }
               strcat(info, ip); // �������� IP � info
               strcat(info, end_r);// �������� ������� ������ � info
               for (i = 0; i < strlen(info); i++) {
                   /* ���������� ��������� � ��� ��������� ������� fputc() */
                   fputc(info[i], fp);
               }
               return 1; //��������� ���������� 1 (������� ������� ���� � ���������� ������)
           
               break;
           case 3: //������� ����������� �� ��������� IP
           
               strcat(info, ip);// �������� IP � info
               strcat(info, end_r);// �������� ������� ������ � info
               for (i = 0; i < strlen(info); i++) {
                   /* ���������� ��������� � ��� ��������� ������� fputc() */
                   fputc(info[i], fp);
               }
               return 1; //��������� ���������� 1 (������� ������� ���� � ���������� ������)
           
               break;
           case 4:
               for (i = 0; i < strlen(info); i++) {
                   /* ���������� ��������� � ��� ��������� ������� fputc() */
                   fputc(info[i], fp);
               }
               return 1; //��������� ���������� 1 (������� ������� ���� � ���������� ������)
           
               break;
           default:
               return 0; //��������� ���������� 0 (�������� ���)
               break;
       }
   } else return 0; //��������� ���������� 0 (�� ������� ������� ����)
}


/**
��������� ������ �������
������� ������ �������
@param code ��� ������� ������
@return errorText ������ ������� ��� �����
**/
int diagnosticError(FILE *log, int code) {
   switch (code) {
       case 1:
           printf("������� ������");
           fputs("������� ������",log);
           return 0;
           break;
       case 2:
           printf("������� ������2");
           fputs("������� ������2",log);
           return 0;
           break;
   }
   return 0;
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



int main(int argc, char *argv[]) {
   char ip[15] = ""; //������ �������� - ip; TODO: ������� �������� �� ������� ����������
   char logName[50] = "log.txt"; //�������� ����� ��� ������������� � start()
   FILE * log;
   int ttl = 1;
   int code = 0;
   strcat(ip, argv);
   switch (start(logName)) {
       case 1: 
           switch (analyze(ip)) {
               case 1: 

                   // Initialize the Winsock2 DLL
                   //
                   if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0) {
                       printf("WSAStartup() failed: %d\n", GetLastError());
                       return -1;
                   }
                   if (argc < 2)
                       usage(argv[0]);
                   if (argc == 3)
                       maxhops = atoi(argv[2]);
                   else
                       maxhops = MAX_HOPS;
                   //
                   // Create a raw socket that will be used to send the ICMP
                   // packets to the remote host you want to ping
                   //
                   sockRaw = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED);
                   if (sockRaw == INVALID_SOCKET) {
                       printf("WSASocket() failed: %d\n", WSAGetLastError());
                       ExitProcess(-1);
                   }
                   //
                   // Set the receive and send timeout values to a second
                   //

                   ret = setsockopt(sockRaw, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout));
                   if (ret == SOCKET_ERROR) {
                       printf("setsockopt(SO_RCVTIMEO) failed: %d\n",
                              WSAGetLastError());
                       return -1;
                   }

                   ret = setsockopt(sockRaw, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout));
                   if (ret == SOCKET_ERROR) {
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
                   if ((dest.sin_addr.s_addr = inet_addr(argv[1])) == INADDR_NONE) {
                       hp = gethostbyname(argv[1]);
                       if (hp)
                           memcpy(&(dest.sin_addr), hp->h_addr, hp->h_length);
                       else {
                           printf("Unable to resolve %s\n", argv[1]);
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

                   if ((!icmp_data) || (!recvbuf)) {
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

                   printf("\nTracing route to %s over a maximum of %d hops:\n\n", argv[1], maxhops);


                   while (1) {
                       int bwrote;

                       // Set the time to live option on the socket
                       //
                       set_ttl(sockRaw, ttl);

                       //
                       // Fill in some more data in the ICMP header
                       //
                       ((IcmpHeader *) icmp_data)->i_cksum = 0;
                       ((IcmpHeader *) icmp_data)->timestamp = GetTickCount();

                       ((IcmpHeader *) icmp_data)->i_seq = seq_no++;
                       ((IcmpHeader *) icmp_data)->i_cksum = checksum((USHORT *) icmp_data, datasize);


                       sendRequest(ip, ttl, log); //�� ����� sendRequest ������ ������� recieveICMP
                       switch (receiveICMP(ttl)){ //���������� ����
                           case 0:

                               switch (Print_log(logName, ip, code, ttl)) {
                                   case 1:
                                   
                                       getreply();
                                       break;
                                   
                                   case 0:

                                       code = 3;
                                       codeOS(log, code);
                                       finish(logName);
                                       break;
                               }
                               break;
                           

                       case 1: //��������� �������� ����� ��� �������� �����
                       
                           switch (Print_log(logName, ip, code, ttl)){
                               case 1:
                                   finish(logName);
                                   break;

                               case 0:
                                    code = 1;
                                    codeOS(log, code);
                                    finish(logName);
                                    break;
                           }

                           break;
                       

                       case 2: //������� ������
                           diagnosticError(log, code);
                           switch (Print_log(logName, ip, code, ttl)) {
                               case 1:
                                   finish(logName);
                                   break;
                              case 0:
                               codeOS(log, code);
                               finish(logName);
                               break;
                               }
                           break;


                       ttl++;
                   }
               } //����� analyze
           case 0:
               switch (Print_log(logName, ip, code, ttl)){
                   case 1:
                       finish(logName);
                       break;

               case 0:
                   code = 1;
                   codeOS(log, code);
                   finish(logName);
                   break;

           }
           break;
           }
       
   case 0: //����� start
   
       code = 2;
       codeOS(log, code);
       finish(logName);
       break;
   }
   return 0;
}


