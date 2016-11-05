#define PAM_SM_SESSION
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

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh,
				   int flags,
				   int argc,
				   const char **argv)
{
  g_pamh = pamh;
  (void)flags;

  if (parse_args(argc, argv) != 0)
    return PAM_SESSION_ERR;

  if (g_debug)
    pam_syslog(g_pamh, LOG_DEBUG, "open_session");


  /* Get the username */
  const char *username = NULL;
  pam_get_item(g_pamh, PAM_USER, (const void **)&username);

  struct passwd *pwd = getpwnam(username);
  if (pwd == NULL)
    {
      pam_syslog(g_pamh, LOG_ERR, "Unable to get pwd");
      return PAM_SUCCESS;
    }

  /* Build argument list */
  char *source = malloc(strlen("/home/.") + strlen(username) + 1);

  if (source == NULL)
  {
    pam_syslog(g_pamh, LOG_ERR, strerror(errno));
    return PAM_SESSION_ERR;
  }

  strcat(strcpy(source, "/home/."), username);
  if (!is_dir(source))
    {
      free(source);
      return PAM_SUCCESS;
    }

  char *target = strdup(pwd->pw_dir);
  if (target == NULL)
  {
    pam_syslog(g_pamh, LOG_ERR, strerror(errno));
    free(source);
    return PAM_SESSION_ERR;
  }

  // Check if the home is not already mounted
  char *mountpoint_command = malloc(strlen("mountpoint -q ") + strlen(target) + 1);
  if (mountpoint_command == NULL)
  {
    pam_syslog(g_pamh, LOG_ERR, strerror(errno));
    free(source);
    free(target);
    return PAM_SESSION_ERR;
  }

  strcat(strcpy(mountpoint_command, "mountpoint -q "), target);
  if (g_debug)
    pam_syslog(g_pamh, LOG_DEBUG, "system: '%s'", mountpoint_command);
  if (system(mountpoint_command) != 0)
  {
    if (g_debug)
      pam_syslog(g_pamh, LOG_DEBUG, "Target is not mounted, prepare to mount it");

    pid_t pid;
    char *args[] = {"encfs", source, target, "-o", "nonempty,allow_root", NULL};

    /* Execute encfs */
    switch (pid = fork())
    {
      case -1:
	pam_syslog(g_pamh, LOG_ERR, "Fork failed");
	return PAM_SERVICE_ERR;

      case 0:

	if ((initgroups(pwd->pw_name, pwd->pw_gid) == -1)
	    || (setgid(pwd->pw_gid) == -1)
	    || (setuid(pwd->pw_uid) == -1))
	{
	  pam_syslog(g_pamh, LOG_ERR, "Dropping permissions failed");
	  return PAM_SERVICE_ERR;
	}

	execvp("encfs", args);
	char errstr[128];

	snprintf(errstr, 127, "%d - %s", errno, strerror(errno));
	pam_syslog(g_pamh, LOG_ERR, "Exec failed - %s", errstr);
	exit(1);
    }

    int status;
    if (waitpid(pid, &status, 0))
    {
      pam_syslog(g_pamh, LOG_ERR, "Timed out waiting for encfs, killing\n");
      kill(pid, SIGKILL);
    }
  }
  else if (g_debug)
    pam_syslog(g_pamh, LOG_DEBUG, "Target is already mounted");

  free(source);
  free(target);

  return PAM_SUCCESS;
}
