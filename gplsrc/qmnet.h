/* QMNET.H
 * Network features.
 * Copyright (c) 2005 Ladybridge Systems, All Rights Reserved
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
 * 05 Dec 05  2.2-18 Extracted from main source files.
 * 16 Sep 04  2.0-1 OpenQM launch. Earlier history details suppressed.
 * END-HISTORY
 *
 * START-DESCRIPTION:
 *
 * This include record extracts commonly used platform dependencies from
 * networking and terminal i/o modules.
 *
 * END-DESCRIPTION
 *
 * START-CODE
 */



   #include <termio.h>
   #include <netdb.h>
   #include <arpa/inet.h>
   #define PASSWD_FILE_NAME "/etc/shadow"
   char * crypt(char * password, char * p);
   #define ASYNCIO
   #define TTY_50_75_134_150_200_1800
   #define TTY_57600_115200_230400




   #include <netinet/in.h>
   #include <netinet/tcp.h>
   #include <sys/socket.h>
   typedef int SOCKET;
   #define INVALID_SOCKET -1
   #define closesocket(s) close(s)
   #define NetError errno

/* END-CODE */
