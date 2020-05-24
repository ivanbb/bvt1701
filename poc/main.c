#include <stdio.h>
#include <stdlib.h>

#pragma pack(4)

#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "data.h"
#include "network.h"
#pragma comment(lib, "ws2_32.lib")


/**
	Open or Make LOG File
	@param *log - Name of the LOG File
	@return int 1 - The file is opened and recorded 
					int	0 - Otherwise
**/

int start(char *log) 
{
	char time_str[128] = "";
	int i = 0;
	int j = 0;
	char info[100] = "     Status: start log ... \r";
	fp = fopen(log, "a+");
	if (fp != NULL)
	{
		time_t time_now = time(NULL);
		struct tm *newtime; // Local time
		newtime = localtime(&time_now); // Converting system time to local time 
		for (i; i < strlen(time_str); i++) 
		{ 
			/* writing the time to the log */
			fputc(time_str[i], fp);
		}
		for (j; j < strlen(info); j++) 
		{
			/* writing the state to the log */
			fputc(info[j], fp);
		}
		return 1;
	}
	//codeOS(FILE *log, int code); TODO
	return 0;
}


/**
	Ip address parsing
	@param *ipAddress - Name of ip adress, to analyze
	@return Go to finish if an error is found()
**/
void analyze(char *ipAddress) 
{
	int i = 0;
	int count_point = 0;

	for (i = 0; i < strlen(ipAddress); i++) // Сheck whether there are characters that are not numbers or dots
	{
		if (!((ipAddress[i] >= '0' && ipAddress[i] <= '9') || ipAddress[i] == '.'))
			printLog("Invalid adress error");
			printf("Invalid adress error\n");
			finish();
	}
	for (i = 0; i < strlen(ipAddress); i++) // Checking the number of points (Must be less than 3)
	{
	if (ipAddress[i] == '.')
		count_point++;
	}
	if (count_point != 3)
		printLog("Invalid adress error");
		printf("Invalid adress error\n");
		finish();
	for (i = 0; i < strlen(ipAddress); i++)// Сhecking the IP numbers
	{
		//string str = "";
		char str[10] = "";
		int p = 0;
		for (; ipAddress[i] != '.' && i < strlen(ipAddress); i++, p++) // Reading the IP octet
		{
			str[p] = ipAddress[i];
		}
		str[p] = '\0';
		if (str[0] != '0') // Checking whether the octet is correct
		{
			int a = atoi(str);
			if (a > 255)
				printLog("Invalid adress error");
				printf("Invalid adress error\n");
				finish();
		} else
		{
			printLog("Invalid adress error");
			printf("Invalid adress error\n");
			finish();
		}
	}
}

/**
	Parsing the received package
	@param *buf
					bytes
					*from
					ttl - Life time package
	@return int 1 - If final packege
					int	0 - Otherwise
**/

int getReply(char *buf, int bytes, SOCKADDR_IN *from, int ttl) 
{
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

	switch (icmphdr->i_type) 
	{
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
			return 0;
			break;
		default:
			printf("non-echo type %d recvd\n", icmphdr->i_type);
			return 0;
			break;
	}
	return 0;
}

/**
	Receives a response from the node
	@param ttl - Life time package
	@return int state (
							0 - the response is received, 
							1 - destination node reached, 
							2 - receiving error)
**/
int receiveICMP(int ttl) 
{
	// Read a packet back from the destination or a router along
	// the way.
	//
	int reply = 0;
	ret = recvfrom(sockRaw, recvbuf, MAX_PACKET, 0, (struct sockaddr *) &from, &fromlen);
	if (ret == SOCKET_ERROR) 
	{
		if (WSAGetLastError() == WSAETIMEDOUT) 
		{
			printf("%2d  Receive Request timed out.\n", ttl);
			return 0;
		}
		return 2;
	}
   //
   // Decode the response to see if the ICMP response is from a
   // router along the way or whether it has reached the destination.
   //
   //  done = decode_resp(recvbuf, ret, &from, ttl);
   reply = getReply(recvbuf, ret, &from, ttl);
   Sleep(100);
   return reply;
}

/**
	Send the ICMP packet to the destination
	@param 	char* ip Address of the destination node
					int ttl The life time of the packet at the current hop
	@return none
**/
int sendRequest(char *ip, int ttl) 
{
	int bwrote;
	int reciveResult = 0;
	bwrote = sendto(sockRaw, icmp_data, datasize, 0, (SOCKADDR *) &dest, sizeof(dest));
	if (bwrote == SOCKET_ERROR)
	{
		if (WSAGetLastError() == WSAETIMEDOUT) {
			printf("%2d  Send request timed out.\n", ttl);
		}
		printf("sendto() failed: %d\n", WSAGetLastError());	
		return 2;
	}
	reciveResult = receiveICMP(ttl);
	return reciveResult;    
}

/**
Conclusion the results of the work
Closes the program and log file
**/
void finish() 
{
	char time_str[128] = "";
	int i = 0;
	char info[100] = "     Status: Close log ... \r";
	if (fp != NULL)
	{
			time_t time_now = time(NULL); 
			struct tm *newtime; // Local time
			newtime = localtime(&time_now); // Converting system time to local time 
			strftime(time_str, 128, "Date:  %x %A %X", newtime); //Converting local time to a text string
			for (i = 0; i < strlen(time_str); i++) {
					/* writing the time to the log */
					fputc(time_str[i], fp);
			}

			for (i = 0; i < strlen(info); i++) {
						/* writing the state to the log */
					fputc(info[i], fp);
			}
			fclose(fp); // Close LOG File
	}
	ExitProcess(-1);
}

/**
	No description TODO: codeOS, Motherfuckers
**/
int codeOS(FILE *log, int code) {  
	char errStr1[] = "�������� ����� �����, ��� ������ - 1";
	char errStr2[] = "�� ��, ��� � ��� 3? � ��, ��� ������ - 2";
	char errStr3[] = "�� ���������� ��� �����(��������), ��� ������ - 3";
	switch (code) 
	{
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
	Writing to a log file
	@param text_prihodit - Text to print
	@return 1 - record success
					0 - record error
**/
int printLog(char* text_prihodit)
{
	struct tm* newtime;
	time_t time_now = time(NULL);
	char time_str[128];

	newtime = localtime(&time_now);
	strftime(time_str, 128, "Date:  %x %A %X\t", newtime);
	strcat(time_str, text_prihodit);

	if (fp != NULL) {
		fprintf(fp, time_str);
		return 1;
	}
	return 0;
	//return codeOS(); TODO
}

/**
Handling network errors
Displays an error in cmd 
Displays an error in the log
@param code - network error code
**/
void diagnosticError(int code) {
	char codeStr[50];
	char finStr[50] = "\nNetwork  error: ";

	itoa (code, codeStr, 10);
	strcat(finStr, codeStr);
	printf(finStr);
	printLog(finStr);
}

int main(int argc, char *argv[]) 
{
	char ip[15] = ""; // TODO: сделать проверку на наличие аргументов…
	char logName[50] = "log.txt"; //name of the file to initialize in start()  FILE * log;
	int ttl = 1;
	int code = 0;

	if (argc < 2) {
		usage(argv[0]);
	}
	
	strcat(ip, argv[1]);
	start(logName);
	//analyze(ip);

	// Initialize the Winsock2 DLL
	if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0) {
		printf("WSAStartup() failed: %d\n", GetLastError());
		return -1;
	}
	
	if (argc == 3)
		maxhops = atoi(argv[2]);
	else
		maxhops = MAX_HOPS;

	createSocket(ip);

	while ((ttl < maxhops) && (!done)) {
		//
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


		code = sendRequest(ip, ttl); // TODO: по схеме sendRequest должен вызвать recieveICMP

		switch(code){
			case 0: // go to the next IP address
				ttl++;
				break;
			case 1: // Reached their destination
				printLog("Traceroute complete succesfully");
				done = 1;
				break;
			case 2: // Errors
				diagnosticError(WSAGetLastError());
				finish();
				break;
		}
	}
	return 0;
}


