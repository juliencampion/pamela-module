#define PAM_SM_SESSION

#include <security/pam_modules.h>

int pam_sm_open_session(pam_handle_t *pamh,
			int flags,
			int argc,
			const char **argv)
{
  (void)pamh;
  (void)flags;
  (void)argc;
  (void)argv;
  return PAM_SUCCESS;
}

int pam_sm_close_session(pam_handle_t *pamh,
			int flags,
			int argc,
			const char **argv)
{
  (void)pamh;
  (void)flags;
  (void)argc;
  (void)argv;
  return PAM_SUCCESS;
}
