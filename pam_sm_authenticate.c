#define PAM_SM_AUTH
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>
#include "common.h"

#define WRITE_END 1
#define READ_END  0

static int waitpid_timeout(pid_t pid, int *status, int options);

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh,
				   int flags,
				   int argc,
				   const char **argv)
{
  g_pamh = pamh;
  (void) flags;

  if (parse_args(argc, argv) != 0)
    return PAM_AUTH_ERR;

  const char *authtok;
  pam_get_item(g_pamh, PAM_AUTHTOK, (const void **)&authtok);
  if (authtok == NULL)
    {
      if (g_debug)
	pam_syslog(g_pamh, LOG_DEBUG, "unable to get password");
      return PAM_AUTH_ERR;
    }

  /* Get the username */
  const char *username = NULL;
  pam_get_item(g_pamh, PAM_USER, (const void **)&username);

  struct passwd *pwd = getpwnam(username);
  if (pwd == NULL)
    {
      pam_syslog(g_pamh, LOG_ERR, "Unable to get pwd");
      return PAM_IGNORE;
    }

  /* Build argument list */
  char *source = malloc(strlen("/home/.") + strlen(username) + 1);

  if (source == NULL)
  {
    pam_syslog(g_pamh, LOG_ERR, strerror(errno));
    return PAM_AUTH_ERR;
  }

  strcat(strcpy(source, "/home/."), username);
  if (!is_dir(source))
    {
      free(source);
      return PAM_IGNORE;
    }

  char *target = strdup(pwd->pw_dir);
  if (target == NULL)
  {
    pam_syslog(g_pamh, LOG_ERR, strerror(errno));
    free(source);
    return PAM_AUTH_ERR;
  }

  // Check if the home is not already mounted
  char *mountpoint_command = malloc(strlen("mountpoint -q ") + strlen(target) + 1);
  if (mountpoint_command == NULL)
  {
    pam_syslog(g_pamh, LOG_ERR, strerror(errno));
    free(source);
    free(target);
    return PAM_AUTH_ERR;
  }

  strcat(strcpy(mountpoint_command, "mountpoint -q "), target);
  if (g_debug)
    pam_syslog(g_pamh, LOG_DEBUG, "system: '%s'", mountpoint_command);
  if (system(mountpoint_command) != 0)
  {
    if (g_debug)
      pam_syslog(g_pamh, LOG_DEBUG, "Target is not mounted, prepare to mount it");

    pid_t pid;
    char *args[] = {"encfs", source, target, "-So", "nonempty,allow_root", NULL};
    int outpipe[2];

    if (pipe(outpipe))
      {
	pam_syslog(g_pamh, LOG_ERR, "Failed to create pipe");
	return PAM_IGNORE;
      }

    // Execute
    switch (pid = fork())
    {
      case -1:
	pam_syslog(g_pamh, LOG_ERR, "Fork failed");
	return PAM_SERVICE_ERR;

      case 0:

	/* if (drop_permissions == 1) */
	if ((initgroups(pwd->pw_name, pwd->pw_gid) == -1)
	    || (setgid(pwd->pw_gid) == -1)
	    || (setuid(pwd->pw_uid) == -1))
	{
	  pam_syslog(g_pamh, LOG_ERR, "Dropping permissions failed");
	  return PAM_SERVICE_ERR;
	}

	close(outpipe[WRITE_END]);
	dup2(outpipe[READ_END], fileno(stdin));
	close(outpipe[READ_END]);
	
	//close(inpipe[READ_END]);
	//dup2(inpipe[WRITE_END], fileno(stdout));
	//close(inpipe[WRITE_END]);
 
	execvp("encfs", args);
	char errstr[128];

	snprintf(errstr, 127, "%d - %s", errno, strerror(errno));
	pam_syslog(g_pamh, LOG_ERR, "Exec failed - %s", errstr);
	exit(1);
    }


    //close(inpipe[WRITE_END]);
    close(outpipe[READ_END]);


    ssize_t len;
    int status;
    if (waitpid(pid, &status, WNOHANG) == 0)
      {
	len = write(outpipe[WRITE_END], authtok, strlen(authtok));
	if ((len != (ssize_t)strlen(authtok))
	    || (write(outpipe[WRITE_END], "\n", 1) != 1))
	  pam_syslog(g_pamh, LOG_ERR, "Did not send password to pipe (%ld sent): %s", len, strerror(errno));
	close(outpipe[WRITE_END]);
      }

    if (waitpid_timeout(pid, &status, 0)) // TODO Remove waitpid_timeout ?
    {
      pam_syslog(g_pamh, LOG_ERR, "Timed out waiting for encfs, killing\n");
      kill(pid, SIGKILL);
    }
    
  }
  else if (g_debug)
    pam_syslog(g_pamh, LOG_DEBUG, "Target is already mounted");

  free(source);
  free(target);
  
  return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t * pamh,
                              int flags,
			      int argc,
			      const char **argv)
{
  (void)pamh;
  (void)flags;
  (void)argc;
  (void)argv;
  return PAM_IGNORE;
}

static int waitpid_timeout(pid_t pid, int *status, int options)
{
    pid_t retval;
    int i = 0;

    do
    {
        retval = waitpid(pid, status, options);
        if (i++ > 10)
        {
            return 1;
        }
    }
    while (retval == 0 || (retval == -1 && errno == EINTR));
    return 0;
}
