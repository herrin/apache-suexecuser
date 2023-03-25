#ifndef __SUEXEC_UTIL_H
#define __SUEXEC_UTIL_H

char *followlinks (
/* Find the real location of the file "startname" by following all
 * symbolic links until you reach the real location */
        char *buf
,       int maxbuf
,       const char *startname
);

char **clean_env(char **environ);

int read_wrapper_permissions (
/* Check the permissions file to determine if the listed program is
 * allowed to run for this user.
 */
        const char *permissionfilename
,       const char *cgifilename
,       char *wrapper_fail_reason
,       int max_fail_len
);


#endif
