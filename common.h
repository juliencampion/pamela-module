#ifndef COMMON_H_
# define COMMON_H_

# include <security/pam_modules.h>
# include <stdbool.h>

extern pam_handle_t *g_pamh;
extern bool g_debug;

int parse_args(int argc, const char **argv);
bool is_dir(const char *path);

#endif
