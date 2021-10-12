#define DEBUG_ENABLE

#ifdef DEBUG_ENABLE
#define pr_debug(...) printf(__VA_ARGS__)
#else
#define pr_debug(...)
#endif

/* Function prototypes */
int search_device_by_ip(char *ip, bool is_ipv6, char *device);