#ifndef __HTTPTRACE_H
#define __HTTPTRACE_H

struct bind_event {
    __u64 tpid;
    __u64 dur_us;
    int family;
    int type;
    int protocol;
    int ret_fd;
};

struct sendmsg_event {
    __u64 tpid;
    __u64 dur_us;
    
    char comm[16];
    char data[100];
    
    int ret;
};

struct event {
    int type;
    union {
        struct bind_event bind;
        struct sendmsg_event sendmsg;
    };
};

#endif