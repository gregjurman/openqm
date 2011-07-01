/* SYSDUMP.C
 * System dump.
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
 * 01 Jul 07  2.5-7 Extensive change for PDA merge.
 * 23 Nov 05  2.2-17 Exported from various sources.
 * 16 Sep 04  2.0-1 OpenQM launch. Earlier history details suppressed.
 * END-HISTORY
 *
 * START-DESCRIPTION:
 *
 * END-DESCRIPTION
 *
 * START-CODE
 */

#include <qm.h>
#include <locks.h>
#include <revstamp.h>
#include <config.h>

   #include <sys/utsname.h>

/* ====================================================================== */

void dump_config(void)
{
 FILE * fu;
 char rec[200+1];


 struct utsname osv;

 uname(&osv);
 printf("Platform: %s, release %s\n  Version %s, machine %s\n",
         osv.sysname, osv.release, osv.version, osv.machine);


 if ((fu = fopen(config_path, "r")) != NULL)
  {
   printf("Dump of config file %s:\n", config_path);
   while(fgets(rec, 200, fu) != NULL)
    {
     printf("%s", rec);
    }
   fclose(fu);
   printf("--- End of config file ---\n\n");
  }
}

/* ======================================================================
   dump_sysseg()  -  Diagnostic print                                     */

void dump_sysseg(bool dump_cfg)
{
 FILE_ENTRY * fptr;
 RLOCK_ENTRY * rlptr;
 GLOCK_ENTRY * glptr;
 SEMAPHORE_ENTRY * semptr;
 USER_ENTRY * uptr;
 int i;
 short int j;
 char * p;



 if (!attach_shared_memory())
  {
   printf("QM is not active\n");
   return;
  }

 if (dump_cfg) dump_config();

// Licence no: 1234567890, system id XXXX-XXXX
// ShMemSize : 123456789
// Sys flags : x12345678  Deadlock  : 1          Errlog    : 1234567
// FDS limit : 123456     Max id    : 123        Netfiles  : x1234
// Next txn  : 12345678   Prt job   : 12345678   Jnl seq   : 1234567 
// qmlnxd pid: 12345678   qmlnxd chk: 12345678
// Sysdir: xxxxxxxxxxxxxxxxxx


 printf("ShMemSize : %-9ld\n", sysseg->shmem_size);
 printf("Sys flags : x%08lX   Deadlock  : %-8d   Errlog    : %d\n",
        sysseg->flags, sysseg->deadlock, sysseg->errlog);
 printf("FDS limit : %-6d      Max id    : %-3d        Netfiles  : x%04X\n",
        sysseg->fds_limit, sysseg->maxidlen, sysseg->netfiles);
 printf("Next txn  : %-8ld    Prt job   : %-8ld   Jnl seq   : %d\n",
        sysseg->next_txn_id, sysseg->prtjob, sysseg->jnlseq);
 printf("qmlnxd pid: %-8d\n", sysseg->qmlnxd_pid);
 printf("Sysdir: %s\n\n", sysseg->sysdir);

 /* Semaphores */

 printf("=== SEMAPHORES ===\n");
 for(i = 0, p = sem_tags, semptr = ((SEMAPHORE_ENTRY *)(((char *)sysseg) + sysseg->semaphore_table));
     i < NUM_SEMAPHORES; i++, p += 3, semptr++)
  {
   printf("%2d %.3s: %3d  %3d\n",
          i, p, (int)(semptr->owner), (int)(semptr->where));
  }
 printf("\n");

/* Users
  0         1         2         3         4         5         6         7
  01234567890123456789012345678901234567890123456789012345678901234567890123456789
   Uid Pid........ Puid Flgs Evnt Origin......... Username........................
  1234 12345678901 1234 1234 1234 123.123.123.123 xxxxxxxxxxxxxxxxxxxxxxxxxx
*/

 printf("=== USER TABLE === (Max %d, map size %d)\n",
        sysseg->max_users, sysseg->hi_user_no);
 printf(" Uid Pid........ Puid Flgs Evnt Origin......... Username\n");
 for(i = 1; i <= sysseg->max_users; i++)
  {
   uptr = UPtr(i);
   if (uptr->uid != 0)
    {
     printf("%4hd %11ld %4d %04X %04X %-15s %s\n",
            uptr->uid, uptr->pid, (int)(uptr->puid),
            (int)(uptr->flags), (int)(uptr->events),
            (uptr->ttyname[0] != '\0')?uptr->ttyname:uptr->ip_addr,
            uptr->username);


     if ((j = uptr->lockwait_index) > 0)
      {
       rlptr = RLPtr(j);
       printf("     Waiting for record lock %d: user %d, file %d, id '%.*s'\n",
              j,
              rlptr->owner, rlptr->file_id,
              rlptr->id_len, rlptr->id);
      }
     else if (j < 0)
      {
       fptr = FPtr(-j);
       printf("     Waiting for file lock: user %d, file %d\n",
              abs(fptr->file_lock), -j);
      }
    }
  }
 printf("\n");

 /* Task locks */
 printf("=== TASK LOCKS ===\n");
 for(i = 0; i < 64; i++)
  {
   if (sysseg->task_locks[i])
    {
     printf("%2d:%-4d  ", i, (int)(sysseg->task_locks[i]));
    }
   else
    {
     printf("%2d:      ", i);
    }
   if ((i % 8) == 7) printf("\n");
  }
 printf("\n");


 /* File table */

 printf("=== FILE TABLE ===\n");
 printf("NUMFILES = %d, Peak = %d, FDS = %d, FDS rotate = %d\n",
        (int)(sysseg->numfiles), (int)(sysseg->used_files),
        (int)(sysseg->fds_limit), (int)(sysseg->fds_rotate));
 printf("Fno Ref FLk  Fvar RLk      Mod MinMod ModVal     FlkTxn       Load Inh FreeOflw\n");

 for(i = 1; i <= sysseg->used_files; i++)
  {
   fptr = FPtr(i);
   if (fptr->ref_ct != 0)
    {
/*
Fno Ref FLk  Fvar RLk      Mod MinMod ModVal     FlkTxn       Load Inh FreeOflw
123  12 123 12345 123 12345678 123456 12345678 12345678 1234567890 123 1234ABCD
*/

     printf("%s (%ld,%ld)\n", fptr->pathname, fptr->device, fptr->inode);

     if (fptr->params.modulus != 0)  /* DH file */
      {
       printf("%3d %3d %3d %5d %3d %8ld %6ld %8ld %8ld %10lu %3d %08lX\n",
              i, (int)(fptr->ref_ct),
              (int)(fptr->file_lock), (int)(fptr->fvar_index),
              (int)(fptr->lock_count),
              fptr->params.modulus, fptr->params.min_modulus,
              fptr->params.mod_value,
              fptr->txn_id,
              (long int)(fptr->params.load_bytes),
              fptr->inhibit_count, fptr->params.free_chain);
      }
     else                            /* Directory file */
      {
       printf("%3d %3d %3d %5d %3d ...... ...... ...... ... ... ..... ......... ... ........\n",
              i, (int)(fptr->ref_ct),
              (int)(fptr->file_lock), (int)(fptr->fvar_index),
              (int)(fptr->lock_count));
      }
    }
  }
 printf("\n");

 /* Record lock table */

 printf("=== RECORD LOCK TABLE ===\n");
 printf("NUMLOCKS = %d, Current = %d, Peak = %d\n",
 (int)(sysseg->numlocks), (int)(sysseg->rl_count), (int)(sysseg->rl_peak));

 printf("RLid  Ct Hash User Fno    Txn Tp Hash     Id\n");
 for(i = 1; i <= sysseg->numlocks; i++)
  {
   rlptr = RLPtr(i);
   if ((rlptr->hash != 0) || (rlptr->count != 0))
    {
/*
RLid  Ct Hash User Fno    Txn Tp Hash     Id
1234 123 1234 1234 123 123456 RU 1234ABCD 40xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
01234567890123456789012345678901234567890123456789012345678901234567890123456789
*/
     printf("%4d %3d %4d %4d %3d %6ld %s %08lX %.*s\n",
            i,
            (int)(rlptr->count),
            (int)(rlptr->hash),
            (int)(rlptr->owner),
            (int)(rlptr->file_id),
            rlptr->txn_id,
            (rlptr->lock_type == L_UPDATE)?"RU":((rlptr->lock_type == L_SHARED)?"RL":"??"),
            rlptr->id_hash,
            min(rlptr->id_len, 40), rlptr->id);
     if (rlptr->waiters) printf("    Waiters = %d\n", rlptr->waiters);
    }
  }
 printf("\n");

 /* Group lock table */

 printf("=== GROUP LOCK TABLE ===\n");
 printf("Max locks = %d, Count = %lu, Wait = %lu, Retry = %lu, Scan = %.1f\n",
        (int)(sysseg->num_glocks),
        sysseg->gl_count, sysseg->gl_wait, sysseg->gl_retry,
        ((float)(sysseg->gl_scan))/max(sysseg->gl_count,1));

 printf("GLid  Ct Hash User Fno Tp Group    GrpCt\n");
 for(i = 1; i <= sysseg->num_glocks; i++)
  {
   glptr = GLPtr(i);
   if ((glptr->hash != 0) || (glptr->count != 0))
    {
/*
GLid  Ct Hash User Fno Tp Group    GrpCt
1234 123 1234 1234 123 GR 1234ABCD    12
*/
     if (glptr->grp_count < 0)
      {
       printf("%4d %3d %4d %4d %3d GW %08lX\n",
              i,
              (int)(glptr->count),
              (int)(glptr->hash),
              (int)(glptr->owner),
              (int)(glptr->file_id),
              glptr->group);
      }
     else
      {
       printf("%3d %3d %3d %3d %3d GR %08lX %5d\n",
              i,
              (int)(glptr->count),
              (int)(glptr->hash),
              (int)(glptr->owner),
              (int)(glptr->file_id),
              glptr->group,
              (int)(glptr->grp_count));
      }
    }
  }
 printf("\n");


 unbind_sysseg();
}

/* END-CODE */
