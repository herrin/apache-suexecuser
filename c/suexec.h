/*
 * suexec.h -- user-definable variables for the suexec wrapper code.
 *             (See README.configure on how to customize these variables.)
 */


#ifndef _SUEXEC_H
#define _SUEXEC_H

/*
 * HTTPD_USER -- Define as the username under which Apache normally
 *               runs.  This is the only user allowed to execute
 *               this program.
 * note: will use unix file system permissions instead
 */

/*
 * UID_MIN -- Define this as the lowest UID allowed to be a target user
 *            for suEXEC.  For most systems, 500 or 100 is common.
 */
#ifndef UID_MIN
#define UID_MIN 100
#endif

/*
 * GID_MIN -- Define this as the lowest GID allowed to be a target group
 *            for suEXEC.  For most systems, 100 is common.
 */
#ifndef GID_MIN
#define GID_MIN 100
#endif

/*
 * USERDIR_SUFFIX -- Define to be the subdirectory under users' 
 *                   home directories where suEXEC access should
 *                   be allowed.  All executables under this directory
 *                   will be executable by suEXEC as the user so 
 *                   they should be "safe" programs.  If you are 
 *                   using a "simple" UserDir directive (ie. one 
 *                   without a "*" in it) this should be set to 
 *                   the same value.  suEXEC will not work properly
 *                   in cases where the UserDir directive points to 
 *                   a location that is not the same as the user's
 *                   home directory as referenced in the passwd file.
 *
 *                   If you have VirtualHosts with a different
 *                   UserDir for each, you will need to define them to
 *                   all reside in one parent directory; then name that
 *                   parent directory here.  IF THIS IS NOT DEFINED
 *                   PROPERLY, ~USERDIR CGI REQUESTS WILL NOT WORK!
 *                   See the suEXEC documentation for more detailed
 *                   information.
 *
 */
#ifndef USERDIR_SUFFIX
#define USERDIR_SUFFIX "www"
#endif
#ifndef WRAPPER_FILE
#define WRAPPER_FILE ".apache-suid"
#endif
#ifndef DOC_ROOT
#define DOC_ROOT "/var/www"
#endif

/*
 * SAFE_PATH -- Define a safe PATH environment to pass to CGI executables.
 *
 */
#ifndef SAFE_PATH
#define SAFE_PATH "/usr/sbin:/usr/bin:/bin"
#endif

#endif /* _SUEXEC_H */
