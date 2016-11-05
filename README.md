# PAMELA

Session service for encfs containers

## Instructions

### Dependencies

- encfs

### Installation

- Install encfs
- Uncomment the line `user_allow_other` in `/etc/fuse.conf`
- Move `pam_pamela.so` to /lib/x86_64-linux-gnu/security
- Add `session optional pam_pamela.so` to the pam configuration,
  for example at the end of `/etc/pam.d/common-session`
