#define _GNU_SOURCE
#define PAM_SM_SESSION

#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <utmp.h>
#include "common.h"

static bool is_last_logged(const char *username);

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh,
				    int flags,
				    int argc,
				    const char **argv)
{
  g_pamh = pamh;
  (void)flags;

  if (parse_args(argc, argv) != 0)
    return PAM_SESSION_ERR;

  const char *username = NULL;
  pam_get_item(g_pamh, PAM_USER, (const void **)&username);

  if (is_last_logged(username))
    {
      struct passwd *pwd = getpwnam(username);
      
      if (pwd != NULL)
	{
	  char *command;
	  asprintf(&command, "fusermount -u %s", pwd->pw_dir);
	  if (command != NULL)
	    {
	      system(command);
	      free(command);
	    }
	  else
	    pam_syslog(g_pamh, LOG_ERR, strerror(errno));
	}
    }
  return PAM_SUCCESS;
}

static bool is_last_logged(const char *username)
{
  struct utmp *utent;
  int number_of_logged = 0;

  setutent();
  while ((utent = getutent()))
    {
      if (utent->ut_type == 7 && strcmp(username, utent->ut_user) == 0)
	++number_of_logged;
    }
  if (g_debug)
    pam_syslog(g_pamh, LOG_DEBUG, "There is %d user logged as %s", number_of_logged, username);
  return number_of_logged == 1;
}
