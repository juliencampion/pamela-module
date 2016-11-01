#include <dirent.h>
#include <security/pam_ext.h>
#include <string.h>
#include <syslog.h>
#include "common.h"

pam_handle_t *g_pamh;
bool g_debug;

int parse_args(int argc, const char **argv)
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

bool is_dir(const char *path)
{
  DIR *dir = opendir(path);
  if (dir == NULL)
    return false;
  closedir(dir);
  return true;
}
