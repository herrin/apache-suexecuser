/*
 * suexec.c -- "Wrapper" support program for suEXEC behaviour for Apache
 *
 * webmaster version -- allows webmastr (whose uid is under 500) to run CGI
 * programs under his uid.
 *
 * Copyright 2004 CrossLink Internet Services
 * Written by William D. Herrin, herrin@dirtside.com
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <regex.h>

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <stdarg.h>

#include "suexec.h"
#include "suexec-util.h"
#include "lowercase.h"

#undef PATH_MAX
#define PATH_MAX 8192
#define AP_MAXPATH PATH_MAX
#define AP_ENVBUF 256
#define LOG_EXEC "stderr"

#define SUEXEC_UMASK 0077

extern char **environ;

#undef UID_MIN
#define UID_MIN 100
#undef GID_MIN
#define GID_MIN 100

void fail(const int errornumber, const char *fmt,...)
{
    va_list ap;

    printf ("Content-Type: text/plain\r\n\r\nsuexec error: ");
    va_start (ap, fmt);
    vprintf (fmt, ap);
    va_end (ap);
    printf ("\r\n");
    exit (errornumber);
}

struct passwd *shifttoeuid(char const *cmd, uid_t *uid, gid_t *gid) {
/* Change very completely to the requested UID and return the pw structure
 * to the caller */
  struct passwd *pw;
  
  /* printf ("euid=%i, uid=%i, egid=%i, gid=%i\n",geteuid(),getuid(),
	getegid(),getgid()); */

  *uid = geteuid();

  /*
   * Error out if attempt is made to execute as root or as
   * a UID less than UID_MIN.  Tsk tsk.
   */
  if ((*uid == 0) || (*uid < UID_MIN)) {
	fail(107,"crit: cannot run as forbidden uid (%d/%s)\n", *uid, cmd);
  }


  setreuid (*uid,*uid);

  pw = getpwuid(*uid);
  if (pw==NULL) {
	fail(102,"crit: invalid uid: (%ld)\n", uid);
  }

  if (strcmp(pw->pw_name,"webmastr")!=0) {
        fail(107,"crit: cannot run as forbidden uid (%d/%s)\n", *uid, cmd);
  }

  *gid = pw->pw_gid;
  /*
   * Error out if attempt is made to execute as root group
   * or as a GID less than GID_MIN.  Tsk tsk.
   */
  if ((*gid == 0) || (*gid < GID_MIN)) {
	fail(108,"crit: cannot run as forbidden gid (%d/%s)\n", *gid, cmd);
  }
  setregid (*gid,*gid);
  /*printf ("euid=%i, uid=%i, egid=%i, gid=%i\n",geteuid(),getuid(),
	getegid(),getgid());*/


  if ((getegid()!=*gid)||(getgid()!=*gid)) {
	fail(109,"emerg: failed to setgid (%ld!=%ld!=%ld: %s)\n", *gid,
		getegid(),getgid(),cmd);
  }

  /* printf ("euid=%i, uid=%i, egid=%i, gid=%i\n",geteuid(),getuid(),
	getegid(),getgid()); */

  return pw;
}

void validate_dirfilestat (
	char const *file
,	struct stat *dir_info
,	struct stat *file_info
,	uid_t uid
,	gid_t gid
,	char const *cwd
,	char const *permfile
) {
    char dn[AP_MAXPATH];	/* dirname */
    int dirlen;

    if ((strlen(file)+2) > AP_MAXPATH) {
	fail(152,"error: very long path\n");
    }
    strcpy (dn,file);
    dirlen = strlen(dn);
    for (dirlen = strlen(dn)-1;  ((dirlen>=0)&&(dn[dirlen]!='/')); dirlen--) {
      dn[dirlen]=0;
    }
    dirlen++;
    if (dirlen<=0) fail(152,"error: no directory in %s\n",file);

    /* fn=file+dirlen;
    while (*fn=='/') fn++; */

    /*
     * Stat the cwd and verify it is a directory, or error out.
     */
    if (((lstat(dn, dir_info)) != 0) || !(S_ISDIR(dir_info->st_mode))) {
	fail(115,"error: cannot stat directory: (%s)\n", dn);
    }

    /*
     * Error out if cwd is writable by others.
     */
    if ((dir_info->st_mode & S_IWOTH) || (dir_info->st_mode & S_IWGRP)) {
	fail(116,"error: directory is writable by others: (%s)\n", dn);
    }

    /*
     * Error out if we cannot stat the program.
     */
    if (lstat(file, file_info) != 0) {
	fail(117,"error: cannot stat file: (%s)\n", file);
    }

    /*
     * Error out if the file is a link and the linked program does not
     * match the security constraints
     */
    if (S_ISLNK(file_info->st_mode)) {
      char buf[AP_MAXPATH],failreason[AP_MAXPATH];

      strncpy (buf,cwd,AP_MAXPATH);
      if (followlinks(buf,AP_MAXPATH,file)==NULL) {
	fail(117,"error: failed to follow links: (%s) cwd=%s\n", file,cwd);
      }

      if (permfile!=NULL) {
	/* Note: assume that the perm files are already checked... */
        if (!read_wrapper_permissions("/etc/apache2/apache-suid",
  	  buf, failreason, AP_MAXPATH)) {
          fail (117,"emerg: wrapper error in /etc/apache2/apache-suid\r\n"
		" on %s\r\n %s\r\n", buf, failreason);
        }
        if (!read_wrapper_permissions(permfile, 
	  buf, failreason, AP_MAXPATH)) {
          fail (117,"emerg: wrapper error in %s\r\n on cgi file %s\r\n %s\r\n",
		permfile, buf, failreason);
        }
      } else {
        fail(117,"error: file is a symbolic link (not allowed): (%s)\n", file);
      }
    }

    /*
     * Error out if the program is writable by others.
     */
    if ( ((file_info->st_mode & S_IWOTH) || (file_info->st_mode & S_IWGRP)) 
	&& (!S_ISLNK(file_info->st_mode)) ) {
	fail(118,"error: file is writable by others: (%s / %s)\n", dn, file);
    }

    /*
     * Error out if the file is setuid or setgid.
     */
    if ((file_info->st_mode & S_ISUID) || (file_info->st_mode & S_ISGID)) {
	fail(119,"error: file is either setuid or setgid: (%s/%s)\n", dn,file);
    }

    /*
     * Error out if the target name/group is different from
     * the name/group of the cwd or the program.
     */
    if ((uid != dir_info->st_uid) ||
	(gid != dir_info->st_gid) ||
	(uid != file_info->st_uid) ||
	(gid != file_info->st_gid)) {
	fail(120,"error: target uid/gid (%ld/%ld) mismatch "
		"with directory (%ld/%ld) or file (%ld/%ld)\n",
		uid, gid,
		dir_info->st_uid, dir_info->st_gid,
		file_info->st_uid, file_info->st_gid);
    }
  return;
}


int main(int argc, char *argv[])
{
    uid_t uid;			/* user information          */
    gid_t gid;			/* target group placeholder  */
    char *target_homedir;	/* target home directory     */
    char *actual_uname;		/* actual user name          */
    char *actual_gname;		/* actual group name         */
    char *prog;			/* name of this program      */
    char *cmd;			/* command to be executed    */
    char failreason[AP_MAXPATH];/* failure reason            */
    char cwd[AP_MAXPATH];	/* current working directory */
    char fn[AP_MAXPATH];	/* total file name           */
    char pfn[AP_MAXPATH];	/* permission file name      */
    struct passwd *pw;		/* password entry holder     */
    struct group *gr;		/* group entry holder        */
    struct stat dir_info;	/* directory info holder     */
    struct stat prg_info;	/* program info holder       */

    prog = argv[0];
    /*
     * If there are a proper number of arguments, set
     * all of them to variables.  Otherwise, error out.
     */
    if (argc < 2) {
	fail(101,"alert: too few arguments (%i)\n",argc);
    }
    cmd = argv[1];

    /* Shift totally to the effective uid, forgetting the old. */
    pw = shifttoeuid(cmd,&uid,&gid);

    /*
     * Save these for later since initgroups will hose the struct
     */
    uid = pw->pw_uid;
    actual_uname = strdup(pw->pw_name);
    target_homedir = strdup(pw->pw_dir);

    /*
     * Check for a leading '/' (absolute path) in the command to be executed,
     * or attempts to back up out of the current directory,
     * to protect against attacks.  If any are
     * found, error out.  Naughty naughty crackers.
     */
    if ((cmd[0] == '/') || (!strncmp(cmd, "../", 3))
	|| (strstr(cmd, "/../") != NULL)) {
        fail(104,"error: invalid command (%s)\n", cmd);
    }

    if ((gr = getgrgid(gid)) == NULL) {
	    fail(106,"crit: invalid target group: (%i)\n", (int) gid);
	}
    actual_gname = strdup(gr->gr_name);
    if (strcmp(actual_gname,"webmastr")!=0)
        fail(106,"crit: invalid target group: (%i)\n", (int) gid);

#ifdef _OSD_POSIX
    /*
     * Initialize BS2000 user environment
     */
    {
	pid_t pid;
	int status;

	switch (pid = ufork(actual_uname))
	{
	case -1:	/* Error */
	    fail(150,"emerg: failed to setup bs2000 environment for user "
		    "%s: %s\n",
		    actual_uname, strerror(errno));
	case 0:	/* Child */
	    break;
	default:	/* Father */
	    while (pid != waitpid(pid, &status, 0))
		;
	    /* @@@ FIXME: should we deal with STOP signals as well? */
	    if (WIFSIGNALED(status)) {
		kill (getpid(), WTERMSIG(status));
	    }
	    exit(WEXITSTATUS(status));
	}
    }
#endif /* _OSD_POSIX */



    /* User is legit, and we're now running as that user. Now, check out
     * the file we plan to run.
     */

    /*
     * Get the current working directory, as well as the proper
     * document root (dependant upon whether or not it is a
     * ~userdir request).  Error out if we cannot get either one,
     * or if the current working directory is not in the docroot.
     * Use chdir()s and getcwd()s to avoid problems with symlinked
     * directories.  Yuck.
     */
    if (getcwd(cwd, AP_MAXPATH) == NULL) {
	fail(111,"emerg: cannot get current working directory\n");
    }

    snprintf (fn,AP_MAXPATH,"%s/%s",cwd,cmd);
    validate_dirfilestat ("/etc/apache2/apache-suid",
	 &dir_info,&prg_info,0,0,NULL,NULL);
    if (!read_wrapper_permissions("/etc/apache2/apache-suid",
	fn, failreason, AP_MAXPATH)) {
      fail (114,"emerg: wrapper error in /etc/apache2/apache-suid\r\n %s",
	failreason);
    }
    snprintf (pfn,AP_MAXPATH,"%s/.apache-suid",target_homedir);
    validate_dirfilestat (pfn,&dir_info,&prg_info,uid,gid,NULL,NULL);
    if (!read_wrapper_permissions(pfn, fn, failreason, AP_MAXPATH)) {
      fail (114,"emerg: wrapper error in %s\r\n %s", pfn, failreason);
    }

    /*
     * Stat the cwd and verify it is a directory, or error out.
     */
    validate_dirfilestat (fn,&dir_info,&prg_info,uid,gid,cwd,pfn);

    /*
     * Error out if the program is not executable for the user.
     * Otherwise, she won't find any error in the logs except for
     * "[error] Premature end of script headers: ..."
     */
    if (!(prg_info.st_mode & S_IXUSR)) {
	fail(121,"error: file has no execute permission: (%s/%s)\n", cwd, cmd);
    }

#ifdef SUEXEC_UMASK
    /*
     * umask() uses inverse logic; bits are CLEAR for allowed access.
     */
    /*if ((~SUEXEC_UMASK) & 0022) {
	log_err("notice: SUEXEC_UMASK of %03o allows "
		"write permission to group and/or other\n", SUEXEC_UMASK);
    }*/
    umask(SUEXEC_UMASK);
#endif /* SUEXEC_UMASK */
    environ = clean_env(environ);

    /*
     * Execute the command, replacing our image with its own.
     */
#ifdef NEED_HASHBANG_EMUL
    /* We need the #! emulation when we want to execute scripts */
    {
	extern char **environ;

	ap_execve(cmd, &argv[1], environ);
    }
#else /*NEED_HASHBANG_EMUL*/
    execv(cmd, &argv[1]);
#endif /*NEED_HASHBANG_EMUL*/

    /*
     * (I can't help myself...sorry.)
     *
     * Uh oh.  Still here.  Where's the kaboom?  There was supposed to be an
     * EARTH-shattering kaboom!
     *
     * Oh well, log the failure and error out.
     */
    fail(255,"emerg: (%d)%s: exec failed (%s)\n", errno, strerror(errno), cmd);
  return 255;
}
