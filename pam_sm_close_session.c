#define _GNU_SOURCE
#define PAM_SM_SESSION

#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include "common.h"

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

  if (g_debug)
    pam_syslog(g_pamh, LOG_DEBUG, "get username: '%s'", username);


  char *command;
  asprintf(&command, "fusermount -u /home/%s", username);
  if (command != NULL)
    {
      system(command);
    }
  else
    pam_syslog(g_pamh, LOG_ERR, strerror(errno));
  free(command);

  return PAM_SUCCESS;
}
