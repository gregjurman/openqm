/* OP_SKT.C
 * Socket interface.
 * Copyright (c) 2007 Ladybridge Systems, All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 * 
 * Ladybridge Systems can be contacted via the www.openqm.com web site.
 * 
 * START-HISTORY:
 * 18 Oct 07  2.6-5 Test in op_openskt() and op_srvrskt() for IP address was
 *                  inadequate.
 * 01 Jul 07  2.5-7 Extensive change for PDA merge.
 * 02 Apr 07  2.5-1 0547 op_srvraddr should allow address as source.
 * 13 Nov 06  2.4-16 Added SKT$INFO.OPEN key to op_sktinfo().
 * 22 Dec 05  2.3-3 Added op_srvraddr().
 * 28 Jul 05  2.2-6 Added SET.SOCKET.MODE() and extended SOCKET.INFO().
 * 30 Jun 05  2.2-3 New module.
 * 16 Sep 04  2.0-1 OpenQM launch. Earlier history details suppressed.
 * END-HISTORY
 *
 * START-DESCRIPTION:
 *
 * This release does not support SSL. The context argument is always passed
 * in as integer zero.
 *
 * skt = ACCEPT.SOCKET.CONNECTION(srvr.skt, timeout)
 *   timeout = max wait time (mS), zero for infinite
 *
 *
 * CLOSE.SOCKET skt
 *
 *
 * srvr.skt = CREATE.SERVER.SOCKET(addr, port{, context})
 *   addr = address to listen on. Leave blank for any local address.
 *
 *
 * skt = OPEN.SOCKET(addr, port, flags{, context})
 *   Flags:
 *      0x0001 = SKT$BLOCKING        Blocking
 *      0x0002 = SKT$NON.BLOCKING    Non-Blocking (default)
 *
 *
 * var = READ.SOCKET(skt, max.len, flags, timeout)
 *   Flags:
 *      0x0001 = SKT$BLOCKING        Blocking     } If neither, uses socket
 *      0x0002 = SKT$NON.BLOCKING    Non-Blocking } default from open.
 *   timeout = max wait time (mS), zero for infinite
 *     
 *
 * var = SET.SOCKET.MODE(skt, key, value)
 *   Keys:
 *      SKT$INFO.BLOCKING   Default blocking mode
 *      SKT$INFO.NO.DELAY   Nagle algorithm disabled?
 *
 * var = SOCKET.INFO(skt, key)
 *   Keys:
 *      SKT$INFO.OPNE       Is this a socket variable?
 *      SKT$INFO.TYPE       Socket type (Server, incoming, outgoing)
 *      SKT$INFO.PORT       Port number
 *      SKT$INFO.IP.ADDR    IP address
 *      SKT$INFO.BLOCKING   Default blocking mode
 *      SKT$INFO.NO.DELAY   Nagle algorithm disabled?
 *
 * var = SERVER.ADDR(name)
 *
 * bytes = WRITE.SOCKET(skt, data, flags, timeout)
 *      0x0001 = SKT$BLOCKING        Blocking     } If neither, uses socket
 *      0x0002 = SKT$NON.BLOCKING    Non-Blocking } default from open.
 *   timeout = max wait time (mS), zero for infinite
 *
 * END-DESCRIPTION
 *
 * START-CODE
 */

#include "qm.h"
#include "keys.h"
#include "qmnet.h"

   #include <sys/time.h>
   #include <sys/wait.h>
   #include <signal.h>

Private char * skt_buff = NULL;
Private int skt_buff_size = 0;

bool socket_wait(SOCKET socket, bool read, int timeout);

/* ======================================================================
   op_accptskt()  -  ACCEPT.SOCKET.CONNECTION                             */

void op_accptskt()
{
 /* Stack:

     |=============================|=============================|
     |            BEFORE           |           AFTER             |
     |=============================|=============================|
 top | Timeout period              | Socket                      |
     |-----------------------------|-----------------------------|
     | Socket reference            |                             |
     |=============================|=============================|
 */

 DESCRIPTOR * descr;
 int timeout;
 SOCKET srvr_skt;
 SOCKET skt;
 SOCKVAR * sockvar;
 DESCRIPTOR result_descr;
 SOCKVAR * sock;
#ifdef _XOPEN_SOURCE_EXTENDED
 size_t n;
#else
 int n;
#endif
 struct sockaddr_in sinRemote;
 struct sockaddr_in sa;


 process.status = 0;

 InitDescr(&result_descr, INTEGER);
 result_descr.data.value = 0;

 /* Get timeout */

 descr = e_stack - 1;
 GetInt(descr);
 timeout = descr->data.value;
 if (timeout == 0) timeout = -1;

 /* Get socket reference */

 descr = e_stack - 2;
 while(descr->type == ADDR) descr = descr->data.d_addr;
 if (descr->type != SOCK) k_not_socket(descr);
 sockvar = descr->data.sock;
 srvr_skt = sockvar->socket_handle;

 /* Wait for connection */

 if (!socket_wait(srvr_skt, TRUE, timeout)) goto exit_op_accptskt;

 n = sizeof(struct sockaddr_in);
 skt = accept(srvr_skt, (struct sockaddr *)&sinRemote, &n);

 /* Create socket descriptor and SOCKVAR structure */

 sock = (SOCKVAR *)k_alloc(100, sizeof(SOCKVAR));
 sock->ref_ct = 1;
 sock->socket_handle = (int)skt;
 sock->flags = SKT_INCOMING;

 n = sizeof(sa);
 getpeername(skt, (struct sockaddr *)&sa, &n);
 strcpy(sock->ip_addr, inet_ntoa(sa.sin_addr));

 n = sizeof(sa);
 getsockname(skt, (struct sockaddr *)&sa, &n);
 sock->port = ntohs(sa.sin_port);

 InitDescr(&result_descr, SOCK);
 result_descr.data.sock = sock;

exit_op_accptskt:
 k_pop(1);
 k_dismiss();

 *(e_stack++) = result_descr;
}

/* ======================================================================
   op_closeskt()  -  CLOSE.SOCKET                                         */

void op_closeskt()
{
 /* Stack:

     |=============================|=============================|
     |            BEFORE           |           AFTER             |
     |=============================|=============================|
 top | Socket reference            |                             |
     |=============================|=============================|
 */

 DESCRIPTOR * descr;

 descr = e_stack - 1;
 while(descr->type == ADDR) descr = descr->data.d_addr;
 if (descr->type != SOCK) k_not_socket(descr);

 k_release(descr);                /* This will close the socket */
 k_pop(1);
}

/* ======================================================================
   op_openskt()  -  OPEN.SOCKET                                           */

void op_openskt()
{
 /* Stack:

     |=============================|=============================|
     |            BEFORE           |           AFTER             |
     |=============================|=============================|
 top | Security context or zero    | Socket                      |
     |-----------------------------|-----------------------------|
     | Flags                       |                             |
     |-----------------------------|-----------------------------|
     | Port                        |                             |
     |-----------------------------|-----------------------------|
     | Server address              |                             |
     |=============================|=============================|

 Returns zero if fails.
 Caller can test with socket variable or check STATUS() value
 */

 DESCRIPTOR * descr;
 int flags;
 int port;
 char server[80+1];
 unsigned long nInterfaceAddr;
 struct sockaddr_in sock_addr;
 int nPort;
 struct hostent * hostdata;
 SOCKET skt;
 DESCRIPTOR result_descr;
 SOCKVAR * sock;
 unsigned int n1, n2, n3, n4;

 process.status = 0;
 InitDescr(&result_descr, INTEGER);
 result_descr.data.value = 0;


 /* Get flags */

 descr = e_stack - 2;

 GetInt(descr);
 flags = descr->data.value;

 /* Get port */

 descr = e_stack - 3;
 GetInt(descr);
 port = descr->data.value;

 /* Get server address */

 descr = e_stack - 4;
 if (k_get_c_string(descr, server, 80) <= 0)
  {
   process.status = ER_BAD_NAME;
   goto exit_open_socket;
  }

 if ((sscanf(server, "%u.%u.%u.%u", &n1, &n2, &n3, &n4) == 4)
     && (n1 <= 255) && (n2 <= 255) && (n3 <= 255) && (n4 <= 255))
  {
   /* Looks like an IP address */
   nInterfaceAddr = inet_addr(server);
  }
 else
  {
   hostdata = gethostbyname(server);
   if (hostdata == NULL)
    {
     process.status = ER_RESOLVE;
     process.os_error = NetError;
     goto exit_open_socket;
    }

   nInterfaceAddr = *((long int *)(hostdata->h_addr));
  }

 nPort= htons(port);

 skt = socket(AF_INET, SOCK_STREAM, 0);
 if (skt == INVALID_SOCKET)
  {
   process.status = ER_NOSOCKET;
   process.os_error = NetError;
   goto exit_open_socket;
  }

 sock_addr.sin_family = AF_INET;
 sock_addr.sin_addr.s_addr = nInterfaceAddr;
 sock_addr.sin_port = nPort;

 if (connect(skt, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) != 0)
  {
   process.status = ER_CONNECT;
   process.os_error = NetError;
   goto exit_open_socket;
  }

 /* Create socket descriptor and SOCKVAR structure */

 sock = (SOCKVAR *)k_alloc(97, sizeof(SOCKVAR));
 sock->ref_ct = 1;
 sock->socket_handle = (unsigned int)skt;
 sock->flags = flags & SKT_USER_MASK;
 strcpy(sock->ip_addr, inet_ntoa(sock_addr.sin_addr));
 sock->port = port;

 InitDescr(&result_descr, SOCK);
 result_descr.data.sock = sock;


exit_open_socket:
 k_dismiss();
 k_pop(2);
 k_dismiss();

 *(e_stack++) = result_descr;
}

/* ======================================================================
   op_readskt()  -  READ.SOCKET                                           */

void op_readskt()
{
 /* Stack:

     |=============================|=============================|
     |            BEFORE           |           AFTER             |
     |=============================|=============================|
 top | Timeout period              | Data                        |
     |-----------------------------|-----------------------------|
     | Flags                       |                             |
     |-----------------------------|-----------------------------|
     | Max len                     |                             |
     |-----------------------------|-----------------------------|
     | Socket                      |                             |
     |=============================|=============================|

 */

 DESCRIPTOR * descr;
 int timeout;
 int max_len;
 int flags;
 SOCKVAR * sock;
 bool blocking;
 int bytes;
 int rcvd_bytes;
 STRING_CHUNK * head = NULL;
 SOCKET skt;


 process.status = 0;

 /* Get timeout period */

 descr = e_stack - 1;
 GetInt(descr);
 timeout = descr->data.value;
 if (timeout == 0) timeout = -1;

 /* Get flags */

 descr = e_stack - 2;
 GetInt(descr);
 flags = descr->data.value;

 /* Get max len */

 descr = e_stack - 3;
 GetInt(descr);
 max_len = descr->data.value;

 if (skt_buff_size < max_len)
  {
   bytes = (max_len + 1023) & ~1023;  /* Round up to 1k multiple */
   if (skt_buff != NULL)
    {
     k_free(skt_buff);
     skt_buff_size = 0;
    }

   skt_buff = (char *)k_alloc(98, bytes);
   if (skt_buff == NULL)
    {
     process.status = ER_MEM;
     goto exit_op_readskt;
    }

   skt_buff_size = bytes;
  }

 /* Get socket */

 descr = e_stack - 4;
 k_get_value(descr);
 if (descr->type != SOCK) k_not_socket(descr);
 sock = descr->data.sock;
 skt = sock->socket_handle;

 /* Determine blocking mode for this read */

 if (flags & SKT_BLOCKING) blocking = TRUE;
 else if (flags & SKT_NON_BLOCKING) blocking = FALSE;
 else blocking = ((sock->flags & SKT_BLOCKING) != 0);

 /* Wait for data to arrive */

 if (!socket_wait(skt, TRUE, (blocking)?timeout:0)) goto exit_op_readskt;

 /* Read the data */

 ts_init(&head, max_len);

 rcvd_bytes = recv(skt, skt_buff, max_len, 0);
 if (rcvd_bytes <= 0)  /* Lost connection */
  {
   process.status = (rcvd_bytes == 0)?ER_SKT_CLOSED:ER_FAILED;
   process.os_error = NetError;
   goto exit_op_readskt;
  }

 ts_copy(skt_buff, rcvd_bytes);
 ts_terminate();

exit_op_readskt:
 k_pop(3);
 k_dismiss();

 InitDescr(e_stack, STRING);
 (e_stack++)->data.str.saddr = head;
}

/* ======================================================================
   op_setskt()  -  SET.SOCKET.MODE()                                      */

void op_setskt()
{
 /* Stack:

     |=============================|=============================|
     |            BEFORE           |           AFTER             |
     |=============================|=============================|
 top | Qualifier                   | 1 = success, 0 = failure    |
     |-----------------------------|-----------------------------|
     | Action key                  |                             |
     |-----------------------------|-----------------------------|
     | Socket reference            |                             |
     |=============================|=============================|
 */

 DESCRIPTOR * descr;
 SOCKVAR * sockvar;
 int key;
 int n;

 process.status = 0;

 /* Get action key */

 descr = e_stack - 2;
 GetInt(descr);
 key = descr->data.value;

 /* Get socket reference */

 descr = e_stack - 3;
 while(descr->type == ADDR) descr = descr->data.d_addr;
 if (descr->type != SOCK) k_not_socket(descr);
 sockvar = descr->data.sock;

 descr = e_stack - 1;   /* Qualifier */

 switch(key)
  {
   case SKT_INFO_BLOCKING:
      GetInt(descr);
      if (descr->data.value) sockvar->flags |= SKT_BLOCKING;
      else sockvar->flags &= ~SKT_BLOCKING;
      break;

   case SKT_INFO_NO_DELAY:
     GetInt(descr);
     n = (descr->data.value != 0);
     setsockopt(sockvar->socket_handle, IPPROTO_TCP, TCP_NODELAY,
                (char *)&n, sizeof(int));
     break;

   case SKT_INFO_KEEP_ALIVE:
     GetInt(descr);
     n = (descr->data.value != 0);
     n = TRUE;
     setsockopt(sockvar->socket_handle, SOL_SOCKET, SO_KEEPALIVE,
                (char *)&n, sizeof(int));
     break;

   default:
      process.status = ER_BAD_KEY;
      break;
  }

 k_dismiss();
 k_dismiss();
 k_dismiss();

 InitDescr(e_stack, INTEGER);
 (e_stack++)->data.value = (process.status == 0);
}

/* ======================================================================
   op_sktinfo()  -  SOCKET.INFO()                                         */

void op_sktinfo()
{
 /* Stack:

     |=============================|=============================|
     |            BEFORE           |           AFTER             |
     |=============================|=============================|
 top | Key                         | Returned information        |
     |-----------------------------|-----------------------------|
     | Socket reference            |                             |
     |=============================|=============================|
 */

 DESCRIPTOR * descr;
 SOCKVAR * sockvar;
 DESCRIPTOR result_descr;
 int key;
 int n;
#ifdef _XOPEN_SOURCE_EXTENDED
 socklen_t n2;
#else
 int n2;
#endif

 InitDescr(&result_descr, INTEGER);
 result_descr.data.value = 0;

 /* Get action key */

 descr = e_stack - 1;
 GetInt(descr);
 key = descr->data.value;

 /* Get socket reference */

 descr = e_stack - 2;
 while(descr->type == ADDR) descr = descr->data.d_addr;
 if ((descr->type != SOCK) && (key != SKT_INFO_OPEN)) k_not_socket(descr);
 sockvar = descr->data.sock;

 switch(key)
  {
   case SKT_INFO_OPEN:
      result_descr.data.value = (descr->type == SOCK);
      break;

   case SKT_INFO_TYPE:
      if (sockvar->flags & SKT_SERVER) result_descr.data.value = SKT_INFO_TYPE_SERVER;
      else if (sockvar->flags & SKT_INCOMING) result_descr.data.value = SKT_INFO_TYPE_INCOMING;
      else result_descr.data.value = SKT_INFO_TYPE_OUTGOING;
      break;

   case SKT_INFO_PORT:
      result_descr.data.value = sockvar->port;
      break;

   case SKT_INFO_IP_ADDR:
      k_put_c_string(sockvar->ip_addr, &result_descr);
      break;

   case SKT_INFO_BLOCKING:
      result_descr.data.value = ((sockvar->flags & SKT_BLOCKING) != 0);
      break;

   case SKT_INFO_NO_DELAY:
      n = 0;
      n2 = sizeof(int);
      getsockopt(sockvar->socket_handle, IPPROTO_TCP, TCP_NODELAY,
                 (char *)&n, &n2);
      result_descr.data.value = (n != 0);
      break;

   case SKT_INFO_KEEP_ALIVE:
      n = 0;
      n2 = sizeof(int);
      getsockopt(sockvar->socket_handle, SOL_SOCKET, SO_KEEPALIVE,
                 (char *)&n, &n2);
      result_descr.data.value = (n != 0);
      break;
  }

 k_pop(1);
 k_dismiss();

 *(e_stack++) = result_descr;
}

/* ======================================================================
   op_srvraddr()  -  SERVER.ADDR()                                        */

void op_srvraddr()
{
 /* Stack:

     |=============================|=============================|
     |            BEFORE           |           AFTER             |
     |=============================|=============================|
 top | Server name                 | Sever address or null       |
     |=============================|=============================|

 */

 DESCRIPTOR * descr;
 char hostname[64+1];
 struct hostent * hostdata;
 struct sockaddr_in sa;
 char ip_addr[15+1] = "";
 unsigned int n1, n2, n3, n4;

 process.status = 0;

 descr = e_stack - 1;
 if (k_get_c_string(descr, hostname, 64) <= 0)
  {
   process.status = ER_BAD_NAME;
   goto exit_op_srvraddr;
  }


 if ((sscanf(hostname, "%d.%d.%d.%d", &n1, &n2, &n3, &n4) == 4)  /* 0547 */
     && (n1 <= 255) && (n2 <= 255) && (n3 <= 255) && (n4 <= 255))
  {
   sprintf(ip_addr, "%u.%u.%u.%u", n1, n2, n3, n4); /* Tidy up format */
   goto exit_op_srvraddr;
  }

 hostdata = gethostbyname(hostname);
 if (hostdata == NULL)
  {
   process.status = ER_SERVER;
   goto exit_op_srvraddr;
  }

 memcpy(&sa.sin_addr, hostdata->h_addr, hostdata->h_length);
 strcpy(ip_addr, inet_ntoa(sa.sin_addr));

exit_op_srvraddr:
 k_dismiss();
 k_put_c_string(ip_addr, e_stack++);
}

/* ======================================================================
   op_srvrskt()  -  CREATE.SERVER.SOCKET                                  */

void op_srvrskt()
{
 /* Stack:

     |=============================|=============================|
     |            BEFORE           |           AFTER             |
     |=============================|=============================|
 top | Security context or zero    | Socket                      |
     |-----------------------------|-----------------------------|
     | Port                        |                             |
     |-----------------------------|-----------------------------|
     | Address                     |                             |
     |=============================|=============================|

 Returns zero if fails.
 Caller can test socket variable or check STATUS() value
 */

 DESCRIPTOR * descr;
 SOCKVAR * sock;
 SOCKET skt;
 int port;
 int nPort;
 char server[80+1];
 struct hostent * hostdata;
 DESCRIPTOR result_descr;
 struct sockaddr_in sinInterface;
 unsigned long nInterfaceAddr = 0;
 unsigned int n1, n2, n3, n4;

 process.status = 0;

 InitDescr(&result_descr, INTEGER);
 result_descr.data.value = 0;


 /* Get port */

 descr = e_stack - 2;
 GetInt(descr);
 port = descr->data.value;

 /* Get server address */

 descr = e_stack - 3;
 if (k_get_c_string(descr, server, 80) < 0)
  {
   process.status = ER_BAD_NAME;
   goto exit_srvrskt;
  }

 if (server[0] != '\0')
  {
   if ((sscanf(server, "%d.%d.%d.%d", &n1, &n2, &n3, &n4) == 4)
        && (n1 <= 255) && (n2 <= 255) && (n3 <= 255) && (n4 <= 255))
    {
     /* Looks like an IP address */
     nInterfaceAddr = inet_addr(server);
    }
   else
    {
     hostdata = gethostbyname(server);
     if (hostdata == NULL)
      {
       process.status = ER_RESOLVE;
       process.os_error = NetError;
       goto exit_srvrskt;
      }

     nInterfaceAddr = *((long int *)(hostdata->h_addr));
    }
  }

 skt = socket(AF_INET, SOCK_STREAM, 0);
 if (skt == INVALID_SOCKET)
  {
   process.status = ER_NOSOCKET;
   process.os_error = NetError;
   goto exit_srvrskt;
  }

 nPort= htons(port);
 sinInterface.sin_family = AF_INET;
 sinInterface.sin_port = nPort;
 sinInterface.sin_addr.s_addr = nInterfaceAddr;

 if (bind(skt, (struct sockaddr*)&sinInterface, sizeof(struct sockaddr_in)) < 0)
  {
   process.status = ER_BIND;
   process.os_error = NetError;
   goto exit_srvrskt;
  }

 listen(skt, SOMAXCONN);

 /* Create socket descriptor and SOCKVAR structure */

 sock = (SOCKVAR *)k_alloc(99, sizeof(SOCKVAR));
 sock->ref_ct = 1;
 sock->socket_handle = (int)skt;
 sock->flags = SKT_SERVER;
 strcpy(sock->ip_addr, inet_ntoa(sinInterface.sin_addr));
 sock->port = port;

 InitDescr(&result_descr, SOCK);
 result_descr.data.sock = sock;


exit_srvrskt:
 k_dismiss();
 k_pop(1);
 k_dismiss();

 *(e_stack++) = result_descr;
}

/* ======================================================================
   op_writeskt()  -  WRITE.SOCKET                                         */

void op_writeskt()
{
 /* Stack:

     |=============================|=============================|
     |            BEFORE           |           AFTER             |
     |=============================|=============================|
 top | Timeout period              | Bytes written               |
     |-----------------------------|-----------------------------|
     | Flags                       |                             |
     |-----------------------------|-----------------------------|
     | Data                        |                             |
     |-----------------------------|-----------------------------|
     | Socket                      |                             |
     |=============================|=============================|

 */

 DESCRIPTOR * descr;
 int timeout;
 int flags;
 SOCKVAR * sock;
 bool blocking;
 int bytes;
 int bytes_sent;
 int total_bytes = 0;
 STRING_CHUNK * str;
 SOCKET skt;
 char * p;

 process.status = 0;

 /* Get timeout period */

 descr = e_stack - 1;
 GetInt(descr);
 timeout = descr->data.value;
 if (timeout == 0) timeout = -1;

 /* Get flags */

 descr = e_stack - 2;
 GetInt(descr);
 flags = descr->data.value;

 /* Get data to write */

 descr = e_stack - 3;
 GetString(descr);
 str = descr->data.str.saddr;

 /* Get socket */

 descr = e_stack - 4;
 k_get_value(descr);
 if (descr->type != SOCK) k_not_socket(descr);
 sock = descr->data.sock;
 skt = sock->socket_handle;

 if (str == NULL) goto exit_op_writeskt;


 /* Determine blocking mode for this write */

 if (flags & SKT_BLOCKING) blocking = TRUE;
 else if (flags & SKT_NON_BLOCKING) blocking = FALSE;
 else blocking = ((sock->flags & SKT_BLOCKING) != 0);


 /* Write the data */

 while(str != NULL)
  {
   p = str->data;
   bytes = str->bytes;   
   do {
       if (!socket_wait(skt, FALSE, (blocking)?timeout:0)) goto exit_op_writeskt;

       bytes_sent = send(skt, p, bytes, 0);
       if (bytes_sent < 0)  /* Lost connection */
        {
         process.status = ER_FAILED;
         process.os_error = NetError;
         goto exit_op_writeskt;
        }

       bytes -= bytes_sent;
       total_bytes += bytes_sent;
       p += bytes_sent;
      } while(bytes);
   str = str->next;
  }

exit_op_writeskt:
 k_pop(2);
 k_dismiss();
 k_dismiss();

 InitDescr(e_stack, INTEGER);
 (e_stack++)->data.value = total_bytes;
}

/* ====================================================================== */

void close_skt(SOCKVAR * sock)
{
 closesocket((SOCKET)(sock->socket_handle));
}

/* ======================================================================
   socket_wait()                                                          */

bool socket_wait(
   SOCKET skt,
   bool read,     /* Read mode? */
   int timeout)
{
 fd_set socket_set;
 fd_set wait_set;
 struct timeval tm;
 sigset_t sigset;

 /* The select() call on Linux systems hangs if the SIGINT signal is
    received while in the function. Set up a mask to allow blocking
    of this signal during the select().                              */

 sigemptyset(&sigset);
 sigaddset(&sigset, SIGINT);

 /* If timeout < 0 (infinite wait), we actually wait in one second
    steps, looking for events each time we wake up.                   */

 if (timeout >= 0)
  {
   tm.tv_usec = (timeout % 1000) * 1000;  /* Fractional seconds and... */
   timeout /= 1000;                       /* ...whole seconds */
   tm.tv_sec = (timeout > 0);
  }
 else
  {
   timeout = 2147482647;                  /* A long time! */
   tm.tv_sec = 1;
   tm.tv_usec = 0;
  }

 FD_ZERO(&socket_set);
 FD_SET(skt, &socket_set);

 while(1)
  {
   wait_set = socket_set;

   sigprocmask(SIG_BLOCK, &sigset, NULL);

   if (select(FD_SETSIZE, (read)?(&wait_set):NULL, (read)?NULL:(&wait_set),
              NULL, &tm) != 0) break;

   sigprocmask(SIG_UNBLOCK, &sigset, NULL);

   if (--timeout <= 0)
    {
     process.status = ER_TIMEOUT;
     return FALSE;
    }

   /* Check for events that must be processed in this loop */

   if (my_uptr->events) process_events();

   if (((k_exit_cause == K_QUIT) && !tio_handle_break())
      || (k_exit_cause == K_TERMINATE))
    {
     return FALSE;
    }

   tm.tv_sec = 1;
   tm.tv_usec = 0;
  }

 return TRUE;
}

/* END-CODE */
