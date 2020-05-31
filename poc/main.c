#include <stdio.h> // standard input / output header file
#include <stdlib.h> // header file of the standard C library, which contains functions that allocate memory, control the process of program execution, type conversion, and other.

#pragma pack(4) // sets packing alignment for members of the structure, union, and class.

#define WIN32_LEAN_AND_MEAN // provides API to socket

#include <winsock2.h> // library for using Winsock2 sockets
#include <ws2tcpip.h> // library for using TCP / IP connection
#include <time.h>        // header file of the standard library of the programming language C, containing types and functions for working with date and time

#include "data.h" // file with structures and variables
#include "network.h" // file with auxiliary functions

#pragma comment(lib, "ws2_32.lib") // library for using Winsock2 sockets
int debug = 0;
char *ip = "";
char logName[50] = "log.txt"; //name of the file to initialize in start()  FILE * log;
int ttl = 1;
int code = 0;
char info_TTL[100] = "     Status: TTL set value "; //запись TTL
char *str_TTL = "";
char res_info_TTL[100] = "";
char codeStr[50] = ""; // Variable for error code
char finStr[50] = "\nNetwork  error: "; // Variable for error text
char isLastHop = 0;

/**
  Function start - creates or opens
  @param *log - log file name
  @return int 1 - Файл открыт и записан file is opened and updated
        int    0 - other cases
**/
int start(int argc, char *argv[]) {

    char time_str[128] = ""; //variable for time
    int i = 0;
    char info[100] = "\n      Status: start log ... \r"; // variable with the status of launching(?) статусом запуска
    if (debug == 0) {
        if (argc < 2) {
          usage(argv[0]);
        }
        strcat(ip, argv[1]);
    }else{
        strcat(ip, "84.242.3.221");
    }
    fp = fopen(logName, "a+");
    if (fp != NULL) {
        time_t time_now = time(NULL);// system time 
        struct tm *newtime = localtime(&time_now); // system time conversion to local time   
        strftime(time_str, 128, "Date:  %x %A %X", newtime); //converts local time into str
        for (i = 0; i < strlen(time_str); i++) {
            fputc(time_str[i], fp); // time into log file Пишется время в лог
        }
        for (i = 0; i < strlen(info); i++) {
            fputc(info[i], fp); // state into lof fileПишется состояние в лог
        }
        return TRUE;
    }
    //codeOS(FILE *log, int code); TODO
    return FALSE;
}


/**
  Parsing and ip ip address check
  @param *ipAddress - ip address name
  @return found mistake - switch to finish
**/

int analyze(char *ipAddress) {
    int i = 0;
    int count_point = 0;
    int hasError = 0;

    for (i = 0;
         i < strlen(ipAddress); i++) // check ip for non-number or non dot symbols, if such symbols are there, return 0
    {
        if (ipAddress[i] == '.')
            count_point++;
    }
    if (count_point == 1)// if there is number return 1
        hasError = 1;

    for (i = 0; i < strlen(ipAddress); i++) //loop if number between 0 and 9 or point
    {
        if (!((ipAddress[i] >= '0' && ipAddress[i] <= '9') ||
              ipAddress[i] == '.')) //check value if number between 0 and 9 or point
        {
            hasError = 1;
        }
    }

    if (count_point != 3)// if more then 3 return 0
        hasError = 1;
    for (i = 0; i < strlen(ipAddress); i++)//check IP numbers
    {
        char str[10] = "";
        int p = 0;
        int a = 0;
        for (; ipAddress[i] != '.' && i < strlen(ipAddress); i++, p++) {// read IP octet
            str[p] = ipAddress[i];
        }
        str[p] = '\0';
        if (str[0] != '0') // check if is a number(does not begin with zero)
            a = atoi(str);
        if (a > 255) {// if ip’s octet is higher than 255 return 0
            hasError = 1;
        }
    }

    if (hasError == 1) {
        printf("Invalid adress error\n");
        return FALSE;
    } else {
        createSocket(ip);
        return TRUE;
    }
}

/**
  Parsing the received package
**/

void getReply() {
    IpHeader *iphdr = NULL;
    IcmpHeader *icmphdr = NULL;
    unsigned short iphdrlen = 0;
    struct hostent *lpHostent = NULL;
    struct in_addr inaddr = ((SOCKADDR_IN *) &from)->sin_addr;
    char *buff = "";
    char *message = "";
    char *ip = "";

    iphdr = (IpHeader *) recvbuf;
    // Number of 32-bit words * 4 = bytes
    iphdrlen = iphdr->h_len * 4;

    if (ret < iphdrlen + ICMP_MIN) {
        return;
    }

    icmphdr = (IcmpHeader *) (recvbuf + iphdrlen);

    switch (icmphdr->i_type) {
        case ICMP_ECHOREPLY:     // Response from destination
            lpHostent = gethostbyaddr((const char *) &((SOCKADDR_IN *) &from)->sin_addr, AF_INET, sizeof(struct in_addr));
            if (lpHostent != NULL) {
                char *hname = lpHostent->h_name;
                ip = inet_ntoa(inaddr);
                message = "";
                snprintf(message,  sizeof hname + sizeof ip + 29*8, "     Status: Recive from IP address %s(%s)", hname, ip);
                printf("%2d  %s (%s)\n", ttl, hname, ip);
                printLog(message);
                isLastHop = 1;
            }
            else{
                // Make log message
                ip = inet_ntoa(inaddr);
                message = "";
                snprintf(message,  sizeof ip + 29*8, "     Status: Recive from IP address %s", ip);
                printf("%2d  %s\n", ttl, ip);
                printLog(message);
                isLastHop = 1;
            }
            break;
        case ICMP_TIMEOUT:      // Response from router along the way
            ip = inet_ntoa(inaddr);
            message = itoa(ttl, buff, 10);
            strcat(message, "    Status: Recive from IP address ");
            strcat(message, ip);
            printf("%2d  %s\n", ttl, ip);
            printLog(message);
            break;
        case ICMP_DESTUNREACH:  // Can't reach the destination at all
            ip = inet_ntoa(inaddr);
            itoa(ttl, message, 10);
            strcat(message, " ");
            strcat(message, ip);
            strcat(message, " reports: Host is unreachable.");
            printf("%2d  %s  reports: Host is unreachable\n", ttl, ip);
            printLog(message);
            break;
        default:
            itoa(ttl, message, 10);
            strcat(message, " non-echo type recvd.");
            printf("non-echo type %d recvd\n", icmphdr->i_type);
            printLog(message);
            break;
    }
    ttl++;
}

/**
  Receives a response from the node
  @return int state (
                    0 - the response is received,
                    1 - destination node reached,
                    2 - receiving error)
**/
int receiveICMP() {
    // Read a packet back from the destination or a router along
    // the way.
    //
    int reply = 0; // Variable for reply code
    char *message = ""; // Variable for message text
    ret = recvfrom(sockRaw, recvbuf, MAX_PACKET, 0, (struct sockaddr *) &from, &fromlen); // Receiving
    if (ttl > maxhops) {
        printf("Reached 30 hops. Stopping program");    // Show message in console
        return 2;
    }
    if (ret == SOCKET_ERROR) {
        if (WSAGetLastError() == WSAETIMEDOUT) {
            itoa(ttl, message, 10); // Convert TTL to *Char
            strcat(message, "    Receive Request timed out."); // Add message to "message" variable

            printf("%2d  Receive Request timed out.\n", ttl);   // Show message in console
            printLog(message);  // Add message to log

            itoa(ttl, str_TTL, 10); //Convert TTL to *Char
            strcpy(res_info_TTL, info_TTL); //Add record TTL
            strcat(res_info_TTL, str_TTL);  // Add TTL to info
            ttl++;
            return 0;
        } else {
            ttl++;
            printf("NetworkError"); // Show message in console
            return 2;
        }
    }
        //
        // Decode the response to see if the ICMP response is from a
        // router along the way or whether it has reached the destination.
        //
        //  done = decode_resp(recvbuf, ret, &from, ttl);
    else {
        if (isLastHop) {
            itoa(ttl, str_TTL, 10); //Convert TTL to *Char
            strcpy(res_info_TTL, info_TTL); //Add record TTL
            strcat(res_info_TTL, str_TTL); // Add TTL to info
            return 1;
        } else {
            itoa(ttl, str_TTL, 10); //Convert TTL to *Char
            strcpy(res_info_TTL, info_TTL); //Add record TTL
            strcat(res_info_TTL, str_TTL); // Add TTL to info
            return 0;
        }
    }
}

/**
  Send the ICMP packet to the destination
  @param     char* ip Address of the destination node
              int ttl The life time of the packet at the current hop
  @return none
**/
void sendRequest(char *ip, int ttl) {
    int bwrote = 0; // Request string variable
    char *errorCode = ""; // Variable for error code
    char *message = ""; // Variable for print message

    set_ttl(sockRaw, ttl); // Set new TTL for next sending

    //
    // Fill in some more data in the ICMP header
    //
    ((IcmpHeader *) icmp_data)->i_cksum = 0;
    ((IcmpHeader *) icmp_data)->timestamp = GetTickCount();

    ((IcmpHeader *) icmp_data)->i_seq = seq_no++;
    ((IcmpHeader *) icmp_data)->i_cksum = checksum((USHORT *) icmp_data, datasize);

    bwrote = sendto(sockRaw, icmp_data, datasize, 0, (SOCKADDR * ) & dest, sizeof(dest)); // Send packet with socket
    if (bwrote == SOCKET_ERROR) { // Check for socket error
        if (WSAGetLastError() == WSAETIMEDOUT) {  // Time out error
            itoa(ttl, message, 10); // Convert error code (Int to *Char)
            strcat(message, " Send request timed out."); // Concat string

            printf("%2d  Send request timed out.\n", ttl); // Print timeout error
            printLog(message); // Add "time out" message to log
        }
        message = "sendto() failed: "; // Error message
        itoa(WSAGetLastError(), errorCode, 10); // Convert error code (Int to *Char)
        strcat(message, errorCode); // Concat strings

        printf("sendto() failed: %d\n", WSAGetLastError()); // Show message in console
        printLog(message); // Add "send failed" message to log
        finish();   // Close programm
    }
}

/**
Conclusion the results of the work
Closes the program and log file
**/
void finish() {
    char time_str[128] = ""; // Variable for end time
    int i = 0; // Counter for strings
    char info[100] = "      Status: stop log ... \r"; // Variable for status
    if (fp != NULL) {
        time_t time_now = time(NULL); // Structure for time variable
        struct tm *newtime = localtime(&time_now); // Converting system time to local time
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
    ExitProcess(-1); // Stop program
}

/**
  No description TODO: codeOS
**/
int codeOS(FILE *log, int code) {
    char errStr1[] = "???? - 1";
    char errStr2[] = "???? - 2";
    char errStr3[] = "???? - 3";
    switch (code) {
        case 1:
            fputs("???? - 1", log);
            printf(errStr1);
            // fwrite(errStr);
            break;
        case 2:
            printf(errStr2);
            fputs("??", log);
            //fwrite(errStr);
            return 1;
        case 3:
            fputs("???? - 3", log);
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
int printLog(char *text_prihodit) {
    time_t time_now = time(NULL); // Structure for time
    struct tm *newtime = localtime(&time_now); // Structure for local time
    char time_str[128] = ""; // String for time
    char end_r[] = "\r"; // End of string
    strftime(time_str, 128, "Date:  %x %A %X\t", newtime); // Format time string
    strcat(time_str, text_prihodit); // Concat time with  income text

    strcat(time_str, end_r); // Concat string with end of string
    if (fp != NULL) {
        fprintf(fp, time_str); // Check if file is open and print to it
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

    itoa(code, codeStr, 10); // Convert to string
    strcat(finStr, codeStr); // Concat strings
    printf(finStr); // Print error
}

int main(int argc, char *argv[]) {
    switch (start(argc, argv)) {
        case TRUE:
            switch (analyze(ip)) {
                case TRUE:
                    while (TRUE) {
                        sendRequest(ip, ttl);
                        switch (receiveICMP()) {
                            case 0: // go to the next IP address
                                printLog(res_info_TTL);
                                getReply();
                                break;
                            case 1: // Reached their destination
                                printLog("     Traceroute complete successfully");
                                finish();
                                break;
                            case 2: // Errors
                                diagnosticError(WSAGetLastError());
                                printLog(finStr);
                                finish();
                                break;
                        }
                    }
                    break;
                case FALSE:
                    printLog("Invalid adress error\n");
                    finish();
                    break;
            }
            break;
        case FALSE:
            finish();
            break;
    }
    return 0;
}
