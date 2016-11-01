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

#define WRITE_END 1
#define READ_END  1

static pam_handle_t *g_pamh;
static bool g_debug;

static int parse_args(int argc, const char **argv);

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
  /*char *authtok = get_password();

  if (authtok == NULL)
    {
      if (g_debug)
	pam_syslog(g_pamh, LOG_DEBUG, "get no password :(");
      return PAM_SESSION_ERR;
    }
  if (g_debug)
    pam_syslog(g_pamh, LOG_DEBUG, "get password: '%s'", authtok);
  */

  /* Get the username */
  const char *username = NULL;
  pam_get_item(g_pamh, PAM_USER, (const void **)&username);

  if (g_debug)
    pam_syslog(g_pamh, LOG_DEBUG, "get username: '%s'", username);


  struct passwd *pwd = getpwnam(username);

  if (pwd != NULL)
    {
      /* Build argument list */
      char *source = malloc(strlen("/home/.") + strlen(username) + 1);
      char *target = strdup(pwd->pw_dir);

      if (source != NULL && target != NULL)
	{
	  strcat(strcpy(source, "/home/."), username);
	  pid_t pid;
	  char *args[] = {"encfs", source, target, "-o", "nonempty", NULL};
	  //int inpipe[2], outpipe[2];

	  /*	    if (pipe(inpipe) || pipe(outpipe))
	    {
	      pam_syslog(g_pamh, LOG_ERR, "Failed to create pipe");
	      return PAM_IGNORE;
	      }*/

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

	      /*close(outpipe[WRITE_END]);
		dup2(outpipe[READ_END], fileno(stdin));
		close(outpipe[READ_END]);
		
		close(inpipe[READ_END]);
		dup2(inpipe[WRITE_END], fileno(stdout));
		close(inpipe[WRITE_END]);*/

		 // For some reason the current directory has to be set to targetpath (or path?) before exec'ing encfs through gdm
		 //chdir(targetpath);
	      execvp("encfs", args);
	      char errstr[128];
	      
	      snprintf(errstr, 127, "%d - %s", errno, strerror(errno));
	      pam_syslog(g_pamh, LOG_ERR, "Exec failed - %s", errstr);
	      exit(1);
	    }
	    
	    int len;
	    (void)len;
	    
	    
	    /*close(inpipe[WRITE_END]);
	      close(outpipe[READ_END]);*/
		 
	    
	    
	    int status;
	    /*if (waitpid(pid, &status, WNOHANG) == 0)
	      {
	      len = write(outpipe[WRITE_END], authtok, (size_t) strlen(authtok));
	      if ((len != (size_t) strlen(authtok))
	      || (write(outpipe[WRITE_END], "\n", 1) != 1))
	      pam_syslog(g_pamh, LOG_ERR, "Did not send password to pipe (%d sent)", len);
	      close(outpipe[WRITE_END]);
	      }*/
	    
	    
	    if (waitpid(pid, &status, 0))
	      {
		pam_syslog(g_pamh, LOG_ERR, "Timed out waiting for encfs, killing\n");
		kill(pid, SIGKILL);
	      }
	}
      else
	pam_syslog(g_pamh, LOG_ERR, strerror(errno));

      free(source);
      free(target);
    }
  else
    pam_syslog(g_pamh, LOG_ERR, "Unable to get pwd");

  //free(authtok);

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

static int parse_args(int argc, const char **argv)
{
  g_debug = false;
  for (int i = 0; i < argc; ++i)
    {
      if (strcmp(argv[i], "debug") == 0)
	g_debug = true;
      else
	{
	  pam_syslog(g_pamh, LOG_ERR, "unknown argument: '%s'", argv[i]);
	  return -1;
	}
    }
  return 0;
}
