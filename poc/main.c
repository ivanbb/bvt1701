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
int debug = 0; // Variable for debug mode
char *ip = ""; // Variable for IP
char logName[50] = "log.txt"; //name of the file to initialize in start()  FILE * log;
int ttl = 1; // Variable for TTL value
int code = 0; // Variable for code 
char info_TTL[100] = "     Status: TTL set value "; // String with TTL status
char *str_TTL = ""; // Variable for conversion TTL to *Char
char res_info_TTL[100] = ""; // Variable for information TTL
char codeStr[50] = ""; // Variable for error code
char finStr[50] = "\nNetwork  error: "; // Variable for error text
char isLastHop = 0; // Variable for last hop

/**
  Function start - creates or opens
  @param *log - log file name
  @return int 1 - Файл открыт и записан file is opened and updated
        int    0 - other cases
**/
int start(int argc, char *argv[]) {

    char time_str[128] = ""; // Variable for time
    int i = 0;
    char info[100] = "\n      Status: start log ... \r"; // Variable with the status of launching()
    if (debug == 0) {
        // Save user IP address
        if (argc < 2) {
          usage(argv[0]); // Show message in console about how to use this programm
        }
        strcat(ip, argv[1]); // Save user IP address in ip variable
    }else{
        strcat(ip, "84.242.3.221"); // IP adress for testing
    }
    fp = fopen(logName, "a+"); // Trying to open log file
    if (fp != NULL) {
        // Open log file
        time_t time_now = time(NULL); // System time variable
        struct tm *newtime = localtime(&time_now); // System time conversion to local time   
        strftime(time_str, 128, "Date:  %x %A %X", newtime); // Convert local time to Char[]
        for (i = 0; i < strlen(time_str); i++) {
            fputc(time_str[i], fp); // Writing time to log file
        }
        for (i = 0; i < strlen(info); i++) {
            fputc(info[i], fp); // Writing state to log file
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
    int count_point = 0; // Variable for count points in IP address
    int hasError = 0; // Variable for check errors

    for (i = 0; i < strlen(ipAddress); i++) // Check ip for non-number or non dot symbols, if such symbols are there, return 0
    {
        if (ipAddress[i] == '.')
            count_point++;
    }
    if (count_point < 3)// If there is number return 1
        hasError = 0;// Set hasError 0
    else if (count_point ==3) 
    {

    for (i = 0; i < strlen(ipAddress); i++) // Loop if number between 0 and 9 or point
    {
        if (!((ipAddress[i] >= '0' && ipAddress[i] <= '9') ||
              ipAddress[i] == '.')) // Check value if number between 0 and 9 or point
        {
            hasError = 1;// Set hasError 1
        }
    }
      
    for (i = 0; i < strlen(ipAddress); i++)//check IP numbers
    {
        char str[10] = ""; // Variable for IP address
        int p = 0;
        int a = 0;
        for (; ipAddress[i] != '.' && i < strlen(ipAddress); i++, p++) { // Read IP address octet
            str[p] = ipAddress[i]; // Save IP address octet
        }
        str[p] = '\0';
        if (str != "")
            hasError = 1;
        if (str[0] != '0') // Check if is a number(does not begin with zero)
            a = atoi(str);
        if (a > 255) {  // If ip’s octet is higher than 255 return 0
            hasError = 1;
        }
    }
    }
    if (hasError == 1) {
        printf("Invalid adress error\n"); // Show error message in console
        return FALSE;
    } else {
        createSocket(ip); // Create soket with IP address
        return TRUE;
    }
}

/**
  Parsing the received package
**/
void getReply() {
    IpHeader *iphdr = NULL; // Init and clear structure IPheader
    IcmpHeader *icmphdr = NULL; // Init and clear structure ICMPheader
    unsigned short iphdrlen = 0; // Init and clear variable
    struct hostent *lpHostent = NULL; // Init and clear structure
    struct in_addr inaddr = ((SOCKADDR_IN *) &from)->sin_addr; // Init structure and conversion IP address from server received
    char *buff = ""; // Buffer variable for conversion
    char *message = ""; // Variable for message
    char *ip = ""; // Variable for IP address

    iphdr = (IpHeader *) recvbuf; // Get data from buffer
    // Number of 32-bit words * 4 = bytes
    iphdrlen = iphdr->h_len * 4; // Calculating count byte, received from server

    if (ret < iphdrlen + ICMP_MIN) { // Check on minimal count byte
        return;
    }

    icmphdr = (IcmpHeader *) (recvbuf + iphdrlen); // Get the type of response from server

    switch (icmphdr->i_type) { // Сhecking the type of response from server
        case ICMP_ECHOREPLY:     // Response from destination
            lpHostent = gethostbyaddr((const char *) &((SOCKADDR_IN *) &from)->sin_addr, AF_INET, sizeof(struct in_addr)); // Get IP address and domain from server
            if (lpHostent != NULL) { // Checking structure for error
                char *hname = lpHostent->h_name; // Get domain name from "hostent" structure
                ip = inet_ntoa(inaddr); // Get IP address from "in_addr" structure
                message = ""; // Clear message variable
                snprintf(message,  sizeof hname + sizeof ip + 29*8, "     Status: Recive from IP address %s(%s)", hname, ip); // Write formatted message in variable
                printf("%2d  %s (%s)\n", ttl, hname, ip);  // Show recive from IP address in console
                printLog(message); // Add status recive from IP address to log file
                isLastHop = 1; // Set last hop
            }
            else{
                ip = inet_ntoa(inaddr);// Get IP address from "in_addr" structure
                message = ""; // Clear message variable
                snprintf(message,  sizeof ip + 29*8, "     Status: Recive from IP address %s", ip);// Write formatted message in variable
                printf("%2d  %s\n", ttl, ip); // Show recive from IP address in console
                printLog(message); // Add status recive from IP address to log file
                isLastHop = 1; // Set last hop
            }
            break;
        case ICMP_TIMEOUT:      // Response from router along the way
            ip = inet_ntoa(inaddr); // Get IP address from "in_addr" structure
            message = itoa(ttl, buff, 10); // Convert TTL (Int to *Char)
            strcat(message, "    Status: Recive from IP address "); // Concat message and status recive
            strcat(message, ip); // Concat message and IP address
            printf("%2d  %s\n", ttl, ip); // Show recive from IP address in console
            printLog(message); // Add status recive to log file
            break;
        case ICMP_DESTUNREACH:  // Can't reach the destination at all
            ip = inet_ntoa(inaddr); // Get IP address from "in_addr" structure
            itoa(ttl, message, 10);  // Convert TTL (Int to *Char)
            strcat(message, " "); // Add space in error message
            strcat(message, ip); // Concat error message and IP address
            strcat(message, " reports: Host is unreachable."); // Concat error message and "Host is unreachable"
            printf("%2d  %s  reports: Host is unreachable\n", ttl, ip);  // Show error message in console
            printLog(message); // Add error "Host is unreachable" to log file
            break;
        default:
            itoa(ttl, message, 10); // Convert TTL (Int to *Char)
            strcat(message, " non-echo type recvd."); // Concat TTL and message
            printf("non-echo type %d recvd\n", icmphdr->i_type); // Show error message in console
            printLog(message); // Add error "non-echo type recvd" to log file
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
    char *message = ""; // variable for message text
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
    itoa(code, codeStr, 10); // Convert code (Int to *Char)
    strcat(finStr, codeStr); // Concat strings
    printf(finStr); // Print error in console
}

int main(int argc, char *argv[]) {
    switch (start(argc, argv)) {  // Starting programm and open log file
        case TRUE:
            switch (analyze(ip)) { // Starting analyze IP-address for checking something error
                case TRUE:
                    while (TRUE) {
                        sendRequest(ip, ttl); // Send request to IP adress
                        switch (receiveICMP()) {
                            case 0: // go to the next IP address
                                printLog(res_info_TTL); // Add message "recive from IP and TTL" to log
                                getReply(); // Parse received data after request 
                                break;
                            case 1: // Reached their destination
                                printLog("     Traceroute complete successfully");  // Add message "traceroute complete" to log
                                finish(); // Close programm
                                break;
                            case 2: // Errors
                                diagnosticError(WSAGetLastError()); // Starting diagnostic with last error code
                                printLog(finStr);   // Add message error to log
                                finish(); // Close programm
                                break;
                        }
                    }
                    break;
                case FALSE:
                    printLog("Invalid adress error\n"); // Add message "invalid adress error" to log
                    finish(); // Close programm
                    break;
            }
            break;
        case FALSE:
            finish(); // Close programm
            break;
    }
    return 0;
}
