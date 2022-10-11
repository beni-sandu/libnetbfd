Change log
==========

All relevant changes are documented in this file.

v0.2 - 2022-10-11
-----------------
A lot of small changes/updates are not mentioned, check commit log for a full history.

* various touch-ups and small clean-ups (removing unused dangling prototypes, fixing typos, fixing comments, etc)
* add an enum for callback return codes
* add 2 new callback scenarios handlers for getting in/out of ADMIN_DOWN
* improve RW lock usage for session access
* various fixes and extra checks around IP addresses and used sockets
* add support for changing DSCP and detection multiplier at runtime
* implement a new interface `bfd_session_change_param()`, more details in DETAILS.md
* preface all debug messages with a [DEBUG] tag, to be easier to spot in large logs
* various BFD protocol fixes around updating states and flags during different scenarios
* implement a `bfd_session_print_stats_log`, similar to its counterpart, but prints to the specified log file
* implement a `print_log` function, which can use a `log_file` parameter for an associated log file
* disable debug messages by default, can be enabled with `DEBUG_ENABLE=1` Makefile flag
* adjust operational TX interval to minimum 1s rate when a session goes down
* add additional info to `bfd_session_print_stats` (detection multiplier, interface name, timestamp, netns)
* fix some memory leaks when cleaning up unconfigured sessions

v0.1 - 2022-03-09
-----------------

First release of the library.