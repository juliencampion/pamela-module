#define PAM_SM_SESSION
#define _POSIX_C_SOURCE 200809L

#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

static pam_handle_t *g_pamh;
static bool g_debug = false;
static bool g_use_first_pass = false;
static bool g_try_first_pass = false;

static int parse_args(int argc, const char **argv);
static char *get_password();

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


  /* Get the password */
  char *authtok = get_password();

  if (authtok == NULL)
    {
      if (g_debug)
	pam_syslog(g_pamh, LOG_DEBUG, "get no password :(");
      return PAM_SESSION_ERR;
    }
  if (g_debug)
    pam_syslog(g_pamh, LOG_DEBUG, "get password: '%s'", authtok);


  /* Get the username */
  const char *username = NULL;
  pam_get_item(g_pamh, PAM_USER, (const void **)&username);

  if (g_debug)
    pam_syslog(g_pamh, LOG_DEBUG, "get username: '%s'", username);

  free(authtok);

  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh,
				    int flags,
				    int argc,
				    const char **argv)
{
  g_pamh = pamh;
  (void)flags;

  if (parse_args(argc, argv) != 0)
    return PAM_SESSION_ERR;

  return PAM_SUCCESS;
}

static int parse_args(int argc, const char **argv)
{
  for (int i = 0; i < argc; ++i)
    {
      if (strcmp(argv[i], "debug") == 0)
	g_debug = true;
      else if (strcmp(argv[i], "use_first_pass") == 0)
	g_use_first_pass = true;
      else if (strcmp(argv[i], "try_first_pass") == 0)
	g_try_first_pass = true;
      else
	{
	  pam_syslog(g_pamh, LOG_ERR, "unknown argument: '%s'", argv[i]);
	  return -1;
	}
    }
  return 0;
}

static char *get_password()
{
  const char *authtok = NULL;

  if (g_try_first_pass || g_use_first_pass)
    pam_get_item(g_pamh, PAM_AUTHTOK, (const void **)&authtok);

  if (g_use_first_pass && authtok == NULL)
    {
      pam_syslog(g_pamh, LOG_ERR, "No authtok provided");
      return NULL;
    }

  if (authtok != NULL)
    return strdup(authtok);

  char *response;
  pam_prompt(g_pamh, PAM_PROMPT_ECHO_OFF, &response, "Password for encrypted container: ");
  return response;
}
