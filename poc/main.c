﻿#include <stdio.h>
#include <stdlib.h>

#pragma pack(4)

#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

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

//этот блок должен быть в мейне, так как функции у нас принимают другие параметры, пришлось глобально
//обьявить
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
       timeout = 100;

char *icmp_data,
       *recvbuf;
BOOL bOpt;
USHORT seq_no = 0;

FILE * fp; // Указатель на log файл


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

/**
Создание лог-файла
**/

int start(char *log) {
   char time_str[128] = ""; //Строка для сохранения преобразованного времени
   int i = 0;
   int j = 0;
   char info[100] = "     Status: start log ... \r"; //запись о состоянии
   fp = fopen(log, "a+"); //Создание файла или открытие существующего файла
   if (fp != NULL) //Если удалось открыть файл
   {
       time_t time_now = time(NULL); //Считываем системное время
       struct tm *newtime;  //Указатель на структуру с локальным временем
       newtime = localtime(&time_now); //Преобразуем системное время в локальное
       for (i; i < strlen(time_str); i++) {
           /* записываем время в лог используя функцию fputc() */
           fputc(time_str[i], fp);
       }
       for (j; j < strlen(info); j++) {
           /* записываем состояние в лог используя функцию fputc() */
          fputc(info[j], fp);
       }
       return 1; //Процедура возвращает 1 (Удалось открыть файл и произвести запись)
   } else return 0; //Процедура возвращает 0 (Не удалось открыть файл)
}


/**
Синтаксический анализ
@param ipAddress
@return int 1-валидный ИП 0-неверный
**/
int analyze(char *ipAddress) {
   int i = 0;
   int count_point = 0;
   for (i = 0; i < strlen(ipAddress); i++) //проверяем есть ли в ip символы не являющиеся цифрой или точкой, если есть то возвращаем 0
   {
       if (!((ipAddress[i] >= '0' && ipAddress[i] <= '9') || ipAddress[i] == '.'))
           return 0;
   }
   for (i = 0; i < strlen(ipAddress); i++) // Проверяем кол-во точек в IP
   {
       if (ipAddress[i] == '.')
           count_point++;
   }
   if (count_point != 3)// если больше 3 то возвращаем 0
       return 0;
   for (i = 0; i < strlen(ipAddress); i++)//проверяем числа IP
   {
       //string str = "";
       char str[10] = "";
       int p = 0;
       for (; ipAddress[i] != '.' && i < strlen(ipAddress); i++, p++) {// считываем октет IP
           str[p] = ipAddress[i];
       }
       str[p] = '\0';
       if (str[0] != '0') // проверяем является ли числом(не начинает ли число с ‘0’)
       {
           int a = atoi(str);
           if (a > 255)// если октет IP больше 255, то возвращаем 0
               return 0;
       } else return 0; //если число начинается с 0 то возвращаем 0
   }
   return 1;// возвращаем 1 если IP правильно введен
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
           return 2;
           break;
       default:
           printf("non-echo type %d recvd\n", icmphdr->i_type);
           return 2;
           break;
   }

}

/**
Получает ответ от узла
Все параметры кроме ттл - глобальные
@param ttl Время жизни пакета
@return int state (0 - ответ получен, 1 - достигнут конечный узел, 2 - ошибка получения)
**/

int receiveICMP(int ttl) {
// Read a packet back from the destination or a router along
   // the way.
   //
   int reply = 0;
   ret = recvfrom(sockRaw, recvbuf, MAX_PACKET, 0, (struct sockaddr *) &from, &fromlen);
   if (ret == SOCKET_ERROR) {
       if (WSAGetLastError() == WSAETIMEDOUT) {
           printf("%2d  Receive Request timed out.\n", ttl);
       }
       printf("recvfrom() failed: %d\n", WSAGetLastError());
       return 2;
   }
   //
   // Decode the response to see if the ICMP response is from a
   // router along the way or whether it has reached the destination.
   //
   //  done = decode_resp(recvbuf, ret, &from, ttl);
   reply = getReply(recvbuf, ret, &from, ttl);
   if (reply == 1) {
       return 1;
       }
   Sleep(100);

   return 0;
}

/**
Отправка запроса
Все нужные параметры - глобальные
Для чего ip и лог - хз
Можно ip можно юзать для вывода на экран
@param char* ip Адрес конечного узла
@param int ttl Время жизни пакета на текущем хопе
@param char* log Название лог-файла
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
    return 0;
}

/**
Вывод результатов работы
Закрывает прогу и лог-файл
@param log название лог-файла
@return none
**/

int finish(char * log) {
   //FILE *fp = fopen(log, "r+"); //Открытие существующего файла
   char time_str[128] = ""; //Указатель на структуру с локальным временем
   int i = 0;
   char info[100] = "     Status: Close log ... \r"; //запись о состоянии
   if (fp != NULL)// Если удалось открыть файл
   {
       time_t time_now = time(NULL); //Считываем системное время
       struct tm *newtime;  //Указатель на структуру с локальным временем
       newtime = localtime(&time_now);  //Преобразуем системное время в локальное
       strftime(time_str, 128, "Date:  %x %A %X", newtime);  //Преобразуем локальное время в текстовую строку
       for (i = 0; i < strlen(time_str); i++) {
           /* записываем время в лог используя функцию fputc() */
           fputc(time_str[i], fp);
       }

       for (i = 0; i < strlen(info); i++) {
           /* записываем состояние в лог используя функцию fputc() */
          fputc(info[i], fp);
       }
       fclose(fp);//Закрываем файл
       return 1; //Процедура возвращает 1 (Удалось открыть файл и произвести запись)
   } else return 0; //Процедура возвращает 0 (Не удалось открыть файл)
}

/**
Диагностика кодов возврата
Обработка ошибок системных
Выводит ошибку текстом
@param code системный код ошибки
@param log название лог-файла
@return errorText ошибка текстом для юзера
**/

int codeOS(FILE *log, int code) {   //printf(“Ошибка записи в лог, закрытие программы”);
   char errStr1[] =  "Превышен лимит хопов, код ошибки - 1";
   char errStr2[] = "то же, что и код 3? я хз, код ошибки - 2";
   char errStr3[] = "не существует лог файла(наверное), код ошибки - 3";
   switch (code) {
       case 1:
           fputs("Превышен лимит хопов, код ошибки - 1", log);
           printf(errStr1);
           // fwrite(errStr);
           break;
       case 2:
           printf(errStr2);
           fputs("??", log);
           //fwrite(errStr);
           return 1;
       case 3:
           fputs("не существует лог файла(наверное), код ошибки - 3", log);
           printf(errStr3);
           // fwrite(errStr);
           break;
   }
   return 0;
}

/**
Вывод данных трассировки на экран
@param char *buf Буфер с пришежшим пакетом ответа
@param int bytes количество байт
@param SOCKADDR_IN *from данные узла от которого пришло сообщение
@param int tll премя жизни пришежшего пакета
**/



/**
Запись в лог файл
@param logMsg сообщение для записи
@return 1 - запись успешна 0 - ошибка записи
@throw ошибка записи
**/

int Print_log(char* log, char* ip, int code, int TTL) {

    //FILE* fp = fopen(log, "r+");
    int i;
    //FILE* fp = fopen(log, "a+");
    time_t time_now = time(NULL);
    struct tm* newtime; 
    char time_str [128];

    newtime = localtime(&time_now);
    strftime(time_str, 128, "Date:  %x %A %X", newtime); 

    if (fp != NULL)
    {
        for (i = 0; i < strlen(time_str); i++) {

            fputc(time_str[i], fp);
        }
        switch (code) {
        case 1:
        {
            char info[100] = "     Status: Invalid IP address format \r";
            for (i = 0; i < strlen(info); i++) {

                fputc(info[i], fp);
            }
            return 1;
        }
        break;
        case 2:
        {
            char info_TTL[100] = "     TTL set value ";
            char str_TTL[10] = "";
            char* end_r_TTL = "\r";
            char info[100] = "     Status: Acknowledgment IP address ";
            char end_r[] = "\r";

            itoa(TTL, str_TTL, 10);
            strcat(info_TTL, str_TTL);

            strcat(info_TTL, end_r_TTL);
            for (i = 0; i < strlen(info_TTL); i++) {

                fputc(info_TTL[i], fp);
            }
            for ( i = 0; i < strlen(time_str); i++) {

                fputc(time_str[i], fp);
            }

            strcat(info, ip);
            strcat(info, end_r);
            for ( i = 0; i < strlen(info); i++) {

                fputc(info[i], fp);
            }
            return 1;
        }
        break;
        case 3:
        {
            char info[100] = "     Status: Successfully connected IP address ";
            char end_r[] = "\r";

            strcat(info, ip);
            strcat(info, end_r);
            for ( i = 0; i < strlen(info); i++) {

                fputc(info[i], fp);
            }
            return 1;
        }
        break;
        case 4: {
            char info[100] = "     Status: Failed to connect \r";

            for ( i = 0; i < strlen(info); i++) {

                fputc(info[i], fp);
            }
            return 1;
        }
              break;
        default:
            return 0;
            break;
        }
    }
    else return 0;
}


/**
Обработка ошибок сетевых
Выводит ошибку текстом
@param code код сетевой ошибки
@return errorText ошибка текстом для юзера
**/

int diagnosticError(FILE *log, int code) {
   switch (code) {
       case 1:
           printf("Сетевая ошибка");
           fputs("Сетевая ошибка",log);
           return 0;
           break;
       case 2:
           printf("Сетевая ошибка2");
           fputs("Сетевая ошибка2",log);
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
   char ip[15] = "192.168.10.1"; //первый аргумент - ip; TODO: сделать проверку на наличие аргументов…
   char logName[50] = "log.txt"; //название файла для инициализации в start()
   FILE * log;
   int ttl = 1;
   int code = 0;
  // strcat(ip, argv); TODO
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
                //   if (argc < 2)
                 //      usage(argv[0]);
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


                   while ((ttl < maxhops) && (!done)) {
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


                       sendRequest(ip, ttl, log); //по схеме sendRequest должен вызвать recieveICMP
                       switch (receiveICMP(ttl)){ //Продолжаем цикл
                           case 0:
                                code = 3;
                               switch (Print_log(logName, ip, code, ttl)) {
                                   case 1:
                                   
                                      // getReply(&buf, bytes, &from, ttl);
                                       break;
                                   
                                   case 0:

                                       code = 3;
                                       codeOS(log, code);
                                       finish(logName);
                                       break;
                               }
                               break;
                           

                       case 1: //Достигнут конечный пункт или превышен лимит
                       code = 3;
                           switch (Print_log(logName, ip, code, ttl)){
                               case 1:
                                   finish(logName);
				done = 1;
                                   break;

                               case 0:
                                    code = 1;
                                    codeOS(log, code);
                                    finish(logName);
					done = 1;
                                    break;
                           }

                           break;
                       

                       case 2: //Сетевая ошибка
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


                   }
                   ttl++;
               } //После analyze
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
       
   case 0: //После start
   
       code = 2;
       codeOS(log, code);
       finish(logName);
       break;
   }
   return 0;
}


