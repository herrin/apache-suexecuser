/* suexec-util.c - utility functions for the suexec programs that are common
 * to all.
 *
 *
 * Copyright 2004 CrossLink Internet Services
 * Written by William D. Herrin, herrin@dirtside.com
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "suexec-util.h"
#include "lowercase.h"

char *followlinks (
/* Find the real location of the file "startname" by following all
 * symbolic links until you reach the real location */
	char *buf
,	int maxbuf
,	const char *startname
) {
  int i, j, done;
  char bufa[2048], bufb[2048];
  char *p, *q, *remainder;
  int maxdepth = 256;

  maxbuf=(maxbuf<2048)?maxbuf:2048;
  maxbuf--;
  p = buf;
  if (startname[0]!='/') {
    if (!getcwd(buf,maxbuf)) return NULL;
    p = buf + strlen(buf);
  }
  j = strlen(startname);
  if ((p-buf+j+2) > maxbuf) return NULL;
  if (p!=buf) {
    *p='/';
    p++;
  }
  strcpy (p,startname);

  /* Scan each element in buf */
  remainder=buf;
  bufa[0]=0;
  done = 0;
  while (!done) {
    if (maxdepth<0) {
      /* printf ("Oops! maxdepth=%i\n",maxdepth); */
      return NULL; 
    }
    if (*remainder==0) done=1;
    /* printf ("Check: %s + %s (%i)\n",bufa,remainder,errno); */
    i = -1;
    if (bufa[0]!=0) {
      i = readlink (bufa,bufb,maxbuf);
      if ((errno>0)&&(errno!=EINVAL)) {
        /* printf ("Oops! Errno=%i\n",errno); */
        return NULL;
      } 
    }
    if (i<0) { /* Not a link, move to the next element */
      if ((remainder[0]=='/')&&(remainder[1]=='/')) {
        remainder+=1;
	continue;
      }
      if ((remainder[0]=='/')&&(remainder[1]=='.')&&(remainder[2]=='/')) {
        remainder+=2;
	continue;
      }
      if ((remainder[0]=='/')&&(remainder[1]=='.')&&(remainder[2]=='.')
		&&(remainder[3]=='/')) {
        remainder+=3;
	p=bufa+strlen(bufa)-1;
	while ((p>=bufa)&&(*p!='/')) p--;
	while ((p>=bufa)&&(*p=='/')) p--;
	p[1]=0;
	continue;
      }
      for (p=remainder,q=bufa+strlen(bufa); (*p=='/'); p++,q++) *q=*p;
      for (; (*p!=0)&&(*p!='/'); p++,q++) *q=*p;
      *q=0;
      remainder=p; 
      continue;
    }
    bufb[i]=0; 
    maxdepth --;
    if (bufb[0]=='/') { /* replace path elements so far */
      if ((strlen(bufb)+strlen(remainder)+2)>maxbuf) return NULL;
      strcpy (bufb+strlen(bufb),remainder);
      strcpy (buf,bufb);
      for (p=buf,q=bufa; (*p=='/'); p++,q++) *q=*p;
      for (; (*p!=0)&&(*p!='/'); p++,q++) *q=*p;
      *q=0;
      remainder=p; 
      done = 0;
      continue;
    }
    /* not /, so add to the remainder and remove the last path element */
    i = strlen(bufb);
    if ((strlen(buf)+i+strlen(remainder)+3)>maxbuf) return NULL;
    strcpy (bufb+i,remainder);
    buf[0]='/';
    strcpy (buf+1,bufb);
    remainder=buf;
    p=bufa+strlen(bufa)-1;
    while ((p>=bufa)&&(*p!='/')) p--;
    while ((p>=bufa)&&(*p=='/')) p--;
    p[1]=0;
    done = 0;
  }

  strcpy (buf,bufa);
  return buf;
}

/* Main segment to test followlinks... strike
  int main (int argc, char **argv) {
    char buf[2048];
    printf ("Real path: %s\n",followlinks (buf,2048, argv[1]));
  }
*/

double wrappercurrentload = -1.0;

double getload () {
  FILE *f;
  char line[100], *s;;

  if (wrappercurrentload>=0.0) return wrappercurrentload;

  f = fopen ("/proc/loadavg","rt");
  if (!f) return (0.5); /* Return a guess of 0.50 if I don't know! */
  fgets (line,99,f);
  fclose (f);
  for (s=line; (*s=='.') || ((*s>='0')&&(*s<='9')); s++) ;
  *s = 0;
  if ((*line)==0) return (0.4); /* Return a guess of 0.40 if I don't know! */

  wrappercurrentload = strtod (line,NULL);
  return wrappercurrentload;
}

int read_wrapper_permissions (
/* Check the permissions file to determine if the listed program is
 * allowed to run for this user.
 * return 1 on success. Return 0 and set wrapper_fail_reason on failure.
 */
	const char *permissionfilename
,	const char *cgifilename
,	char *wrapper_fail_reason
,	int max_fail_len
) {
  FILE *f;
  struct stat wrapstat;
  char s[2048], *p;
  int vallen, cgifnlen;

  if (((lstat(permissionfilename, &wrapstat)) != 0) 
	|| !(S_ISREG(wrapstat.st_mode))) {
	snprintf (wrapper_fail_reason,max_fail_len,
		"%s is not a plain text file", permissionfilename);
        return 0;
  }

  cgifnlen = strlen(cgifilename);
  f = fopen(permissionfilename,"r");
  if (f==NULL) {
    snprintf (wrapper_fail_reason,max_fail_len,
		"could not open %s", permissionfilename);
    return 0;
  }
  while (!feof(f)) {
    if (!fgets(s,2047,f)) {
      fclose(f);
      snprintf (wrapper_fail_reason,max_fail_len,
		"no explicit authorization in %s before end seeking %s",
		permissionfilename, cgifilename);
      return 0;
    }
    if (s[0]=='#') continue;
    for (p = s + strlen(s)-1; (p>=s)&& 
	((*p=='\r')||(*p=='\n')||(*p==' ')||(*p=='\t')); p--) *p=0;
    for (p=s; (*p!=0)&&(*p!=':'); p++) ;
    if (*p==':') {
      *p=0;
      p++;
      while ((*p==' ')||(*p=='\t')) p++;
    }
    vallen = strlen(p);
    strlwr (s);
    /* printf ("WRAPPER: command %s\n",s); */
    if (!strcmp(s,"run")) {
      if (vallen<1) continue;
      /* printf ("RUN: compare %s to %s\n",p,cgifilename); */
      if (p[vallen-1]!='*') {
	if (vallen!=cgifnlen) continue;
        if (!strcmp(p,cgifilename)) {
          fclose (f);
          return 1;
	}
	continue;
      }
      if (!strnncmp (p,cgifilename,vallen-1)) {
        fclose (f);
        return 1;
      }
      continue;
    }
    if (!strcmp(s,"stop")) {
      if (vallen<1) {
        fclose(f);
	snprintf (wrapper_fail_reason,max_fail_len,"empty stop: line in %s",
		permissionfilename);
        return 0;
      }
      if (p[vallen-1]!='*') {
	if (vallen!=cgifnlen) continue;
        if (!strcmp(p,cgifilename)) {
          fclose (f);
	  snprintf (wrapper_fail_reason,max_fail_len,
		"matched line stop:%s in %s", p,permissionfilename);
          return 0;
	}
	continue;
      }
      if (!strnncmp (p,cgifilename,vallen-1)) {
        fclose (f);
        snprintf (wrapper_fail_reason,max_fail_len,
		"matched line stop:%s in %s", p,permissionfilename);
        return 0;
      }
      continue;
    }
    if (!strcmp(s,"maxload")) {
      /* Check the load average here */
      double load, maxload;

      maxload = strtod(p,NULL);
      load = getload();
      if (load>maxload) {
        snprintf (wrapper_fail_reason,max_fail_len,
		"current load average %f > maximum %f in %s. Try again later.", 
		load, maxload, permissionfilename);
        fclose(f);
        return 0;
      }
      continue;
    }
    snprintf (wrapper_fail_reason,max_fail_len,
		"unknown command '%s' in %s", s, permissionfilename);
    fclose(f);
    return 0;
  }
  fclose(f);
  snprintf (wrapper_fail_reason,max_fail_len,"no explicit authorization in %s",
		permissionfilename);
  return 0;
}

typedef struct {
  char *name;
  int len;
} safelisttype;

safelisttype safe_env_lst[] =
{
    {.name="AUTH_TYPE",.len=-1},
    {.name="CONTENT_LENGTH",.len=-1},
    {.name="CONTENT_TYPE",.len=-1},
    {.name="DATE_GMT",.len=-1},
    {.name="DATE_LOCAL",.len=-1},
    {.name="DOCUMENT_NAME",.len=-1},
    {.name="DOCUMENT_PATH_INFO",.len=-1},
    {.name="DOCUMENT_ROOT",.len=-1},
    {.name="DOCUMENT_URI",.len=-1},
    {.name="FILEPATH_INFO",.len=-1},
    {.name="GATEWAY_INTERFACE",.len=-1},
    {.name="LAST_MODIFIED",.len=-1},
    {.name="PATH_INFO",.len=-1},
    {.name="PATH_TRANSLATED",.len=-1},
    {.name="QUERY_STRING",.len=-1},
    {.name="QUERY_STRING_UNESCAPED",.len=-1},
    {.name="REMOTE_ADDR",.len=-1},
    {.name="REMOTE_HOST",.len=-1},
    {.name="REMOTE_IDENT",.len=-1},
    {.name="REMOTE_PORT",.len=-1},
    {.name="REMOTE_USER",.len=-1},
    {.name="REDIRECT_QUERY_STRING",.len=-1},
    {.name="REDIRECT_STATUS",.len=-1},
    {.name="REDIRECT_URL",.len=-1},
    {.name="REQUEST_METHOD",.len=-1},
    {.name="REQUEST_URI",.len=-1},
    {.name="SCRIPT_FILENAME",.len=-1},
    {.name="SCRIPT_NAME",.len=-1},
    {.name="SCRIPT_URI",.len=-1},
	/* SCRIPT_URI seems to come out wrong, when it exists at all! */
    {.name="SCRIPT_URL",.len=-1},
    {.name="SERVER_ADMIN",.len=-1},
    {.name="SERVER_NAME",.len=-1},
    {.name="SERVER_ADDR",.len=-1},
    {.name="SERVER_PORT",.len=-1},
    {.name="SERVER_PROTOCOL",.len=-1},
    {.name="SERVER_SOFTWARE",.len=-1},
    {.name="UNIQUE_ID",.len=-1},
    {.name="USER_NAME",.len=-1},
    {.name="TZ",.len=-1},
    {.name="REDIRECT_HTTPS",.len=-1},
    {.name="HTTPS",.len=-1},
    {.name=NULL,.len=-1}
};

safelisttype specially_cleaned_env_lst[] =
{
    {.name="DOCUMENT_ROOT",.len=-1},
    {.name=NULL,.len=-1}
};


#ifndef SAFE_PATH
#define SAFE_PATH "/usr/sbin:/usr/bin:/bin"
#endif
#define AP_ENVBUF 256

char **clean_env(char **environ)
{
    char pathbuf[512];
    char **cleanenv;
    char **ep;
    int cidx = 0;
    int idx, httphostlen=0, skipit, specially_cleaned=0;
    const char *scriptfilename=NULL, *docroot=NULL;
    char *httphost=NULL, *s, *p;

    if ((cleanenv = (char **) calloc(AP_ENVBUF, sizeof(char *))) == NULL) {
        printf ("Content-type: text/plain\r\n\r\nsuexec emerg: failed to malloc memory for environment\n");
        exit(120);
    }

    sprintf(pathbuf, "PATH=%s", SAFE_PATH);
    cleanenv[cidx] = strdup(pathbuf);
    cidx++;


    /* Check the vars. */
    for (ep = environ; *ep ; ep++) {
      if (!strnncmp(*ep, "HTTP_HOST=",10)) httphost = strdup((*ep)+10);
      else if (!strnncmp(*ep, "SCRIPT_FILENAME=",16))
                scriptfilename = (*ep)+16;
      else if (!strnncmp(*ep, "DOCUMENT_ROOT=",14)) docroot = *ep;
    }
    if (httphost) {
      for (s = httphost; *s; s++) if (*s==':') *s=0;
      httphostlen = strlen(httphost);
    }
    if (httphost && scriptfilename && 
	((strnncmpi(scriptfilename,"/home/",6)==0) ||
	 (strnncmpi(scriptfilename,"/var/www/virtual/",17)==0) )
	) {
      /* Fake a <Virtual> for these guys! */
      specially_cleaned=1;
      /* set DOCROOT to a reasonable part of SCRIPT_FILENAME */
      s = (char*) malloc (sizeof(char) * (20 + strlen(scriptfilename)));
      sprintf (s,"DOCUMENT_ROOT=%s",scriptfilename);
      if (strnncmpi(s+14,"/home/",6)==0) {
        /* use the part ending with /www/ (user home dir) */
        for (p=s+20; *p && strnncmpi(p,"/www/",5); p++);
        if (*p) p[4]=0;
      } else if (strnncmpi(s+14,"/var/www/virtual/",17)==0) {
	/* /var/www/virtual/name/www.crosslink.net/ */
        /* Use the part ending with the host name */
	if (strnncmpi(s+14+17,"name/",5)==0) {
          for (p=s+14+17+5; *p && strnncmpi(p,httphost,httphostlen); p++);
          if (*p) {
            for (; *p && (*p!='/'); p++) ;
            *p=0;
          }
        } else { /* /var/www/virtual/12/10.11.12.13/ */
          for (p=s+14+17; (*p>='0') && (*p<='9') ; p++);
          if (*p=='/') {
            for (p++; ((*p>='0') && (*p<='9')) || (*p=='.') ; p++);
            if (*p=='/') *p = 0;
          }
        }
      } else { /* Use existing DOCUMENT_ROOT */
        free (s);
        s = NULL;
        if (docroot) s = strdup (docroot);
      }
      if (s) {
        cleanenv[cidx] = s;
        cidx++;
      }

      /* PATH_TRANSLATED comes out wrong! But in old version too. Ignore? */
  
    }

    /* initialize safe_env_list */
    for (idx = 0; safe_env_lst[idx].name; idx++) {
      safe_env_lst[idx].len = strlen(safe_env_lst[idx].name);
    }
    for (idx = 0; specially_cleaned_env_lst[idx].name; idx++) {
      specially_cleaned_env_lst[idx].len = 
	strlen(specially_cleaned_env_lst[idx].name);
    }


    for (ep = environ; *ep && cidx < AP_ENVBUF-1; ep++) {
        if (specially_cleaned) {
          skipit = 0;
          for (idx = 0; specially_cleaned_env_lst[idx].name; idx++) {
            if (!strnncmp(*ep, specially_cleaned_env_lst[idx].name,
                       specially_cleaned_env_lst[idx].len )) {
              skipit = 1;
              break;
            }
          }
	  if (skipit) continue;
        }
        if (!strnncmp(*ep, "HTTP_", 5)) {
            cleanenv[cidx] = *ep;
            cidx++;
        }
        else {
            for (idx = 0; safe_env_lst[idx].name; idx++) {
                if (!strnncmp(*ep, safe_env_lst[idx].name,
                             safe_env_lst[idx].len )) {
                    cleanenv[cidx] = *ep;
                    cidx++;
                    break;
                }
            }
        }
    }

    cleanenv[cidx] = NULL;

    return cleanenv;
}

