#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "httptrace.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct bind_args_t{
    u64 dur_us;
    int family;
    int type;
    int protocal;
};

// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 10240);
//     __type(key, u64);
//     __type(value, u64);
// } ts_map SEC("maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct bind_args_t);
} bind_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

//观测http请求中的bind系统调用，该步骤用于绑定ip地址与端口号，从而监听请求
SEC("tracepoint/syscalls/sys_enter_bind")
int tracepoint__syscalls_sys_enter_bind(struct trace_event_raw_sys_enter *ctx){
    u64 id = bpf_get_current_pid_tgid();
    // pid_t pid, tid;
    // pid = id>>32;
    // tid = (u32)tid;

    // address family ，如AF_INET
    int family = (int) BPF_CORE_READ(ctx, args[0]);
    // 套接字的类型
    int type = (int) ctx->args[1];
    // 使用的传输协议，通常设置为0以表示使用默认协议。对TP套接字为IPPROTO_TCP，UDP套接字为IPPROTO_UDP
    int protocol = (int) BPF_CORE_READ(ctx, args[2]);

    u64 curr_ts = bpf_ktime_get_ns();

    struct bind_args_t  bind_args = {};

    bind_args.family = family;
    bind_args.type = type;
    bind_args.protocal = protocol;

    bind_args.dur_us = curr_ts;

    bpf_map_update_elem(&bind_args_map, &id, &bind_args, BPF_ANY);
    //bpf_map_update_elem(&ts_map, &id, &curr_ts, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_bind")
int tracepoint__syscalls_sys_exit_bind(struct trace_event_raw_sys_exit *ctx){
    u64 id = bpf_get_current_pid_tgid();

    struct bind_args_t *bd;
    bd = bpf_map_lookup_elem(&bind_args_map, &id);
    if(bd == NULL){
        return 0;
    }

    bpf_map_delete_elem(&bind_args_map, &id);
    return 0;
}

struct sendmsg_args_t {
    int fd;
    struct user_msghdr* msg;
    int flags;
    u64 dur_us;
};

struct{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct sendmsg_args_t);
} sendmsg_args_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int tracepoint__syscalls_sys_enter_sendmsg(struct trace_event_raw_sys_enter *ctx){
    u64 id = bpf_get_current_pid_tgid();

    struct user_msghdr* msghdr = (struct user_msghdr *) BPF_CORE_READ(ctx, args[1]);
    int fd = (int) ctx->args[0];
    int flags = (int) ctx->args[2];

    u64 curr_ts = bpf_ktime_get_ns();

    struct sendmsg_args_t args = {};
    args.dur_us = curr_ts;
    args.flags = flags;
    args.fd = fd;
    args.msg = msghdr;

    bpf_map_update_elem(&sendmsg_args_map, &id, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendmsg")
int tracepoint__syscalls_sys_exit_recvmsg(struct trace_event_raw_sys_exit *ctx){
    u64 id = bpf_get_current_pid_tgid();

    struct sendmsg_args_t *args;
    args = bpf_map_lookup_elem(&sendmsg_args_map, &id);
    if(args==NULL){
        return 0;
    }

    int ret = ctx->ret;

    //struct user_msghdr *hdr = args->msg;

    // int len;
    // long r1 = bpf_probe_read_kernel(&len, sizeof(__kernel_size_t), hdr->msg_iovlen);
    // if(r1<0){
    //     return 0;
    // }

    struct event e ={};
    e.type = 1;
    e.sendmsg.ret = ret;
    e.sendmsg.tpid = id;

    //TODO

    // if(iov){
    //     for(int i=0;i<hdr->msg_iovlen;i++){
    //         if(bpf_probe_read_user_str())
    //     }
    // }

    char data[50];

    bpf_probe_read(&data, args->msg->msg_iov[0].iov_len, args->msg->msg_iov[0].iov_base);

    bpf_get_current_comm(&e.sendmsg.comm, sizeof(e.sendmsg.comm));

    if(args->dur_us==0){
        return 0;
    }

    u64 dur_us = bpf_ktime_get_ns()-args->dur_us;
    e.sendmsg.dur_us = dur_us;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

    bpf_map_delete_elem(&sendmsg_args_map, &id);

    return 0;
}


