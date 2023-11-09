#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
// #include <linux/in.h>
// #include <linux/in6.h>
//#include <linux/socket.h>
// #include <arpa/inet.h>

#include <net/sock.h>
// #include <linux/net.h>
#include <sys/socket.h>
#include "socket_trace.h"


char LICENSE[] SEC("license") = "Dual BSD/GPL";

//syscall timeline存储
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u64);
	__type(value, u64);
} connect_time SEC(".maps");

//tracepoint syscalls/connect的相关参数列表
struct args_connect_t
{
    int fd;
    struct sockaddr * uservaddr;
    int addrlen;
};


//存放connect系统调用的部分指标
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u64);
	__type(value, struct args_connect_t);
} args_connect_map SEC(".maps");

//connect ring缓冲区，与用户态进行数据交互
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} sys_connect_rb SEC(".maps");


// 观测connect enter 
SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__syscalls_sys_enter_connect(struct trace_event_raw_sys_enter *ctx){
    u64 id = bpf_get_current_pid_tgid();
	// pid_t pid, tid;
	// pid = id>>32;
	// tid = (u32)id;

	struct args_connect_t args = {};
	args.uservaddr = (struct sockaddr *) ctx->args[1];
	if(args.uservaddr->sa_family != AF_INET || args.uservaddr->sa_family!=AF_INET6){
		return 0;
	}
	args.addrlen = ctx->args[2];

	bpf_map_update_elem(&args_connect_map, &id, &args, BPF_ANY);

	u64 ktime = bpf_ktime_get_ns();
	bpf_map_update_elem(&connect_time,&id, &ktime, BPF_ANY);

	return 0;
}

//观测connect exit
SEC("tracepoint/syscalls/sys_exit_connect")
int tracepoint__syscalls_sys_exit_connect(struct trace_event_raw_sys_exit *ctx){
	u64 id = bpf_get_current_pid_tgid();

	u64 *startTime = bpf_map_lookup_elem(&connect_time, &id);
	if(startTime==NULL){
		return 0;
	}

	u64 dur_us = bpf_ktime_get_ns() - *startTime;

	struct args_connect_t *ag;

	ag = bpf_map_lookup_elem(&args_connect_map, &id);
	if(ag==NULL){
		return 0;
	}

	struct sockaddr * uvaddr = ag->uservaddr;

	long ret = -ctx->ret;

	struct syscall_connect_event * e;
	
	e = bpf_ringbuf_reserve(&sys_connect_rb, sizeof(*e), 0);
	if(!e){
		return 0;
	}

	if(uvaddr->sa_family==AF_INET){
		struct sockaddr_in * s = (struct sockaddr_in *) uvaddr;

		u16 port = (s->sin_port>>8) | ((s->sin_port<<8) & 0xff00); //socket与x86使用不同的字节序，因此对从socket中获取的port进行模式转换

		char str[INET_ADDRSTRLEN];
		const char * p = inet_ntop(AF_INET, &s->sin_addr.s_addr, str, sizeof(str));

		e->dur_us = dur_us;
		bpf_probe_read_user_str(&e->address, sizeof(e->address), p);
		e->port = port;
		e->retval = ret;
		e->sa_family = AF_INET;
		
		bpf_ringbuf_submit(e, 0);
	}else{
		struct sockaddr_in6 * s6 = (struct sockaddr_in6 *) uvaddr;
		
		u16 port = (s6->sin6_port>>8) | ((s6->sin6_port<<8) & 0xff00);

		char str[INET6_ADDRSTRLEN];
		const char *p = inet_ntop(AF_INET6, s6->sin6_addr.in6_u.u6_addr8, str, sizeof(str));

		e->dur_us = dur_us;
		bpf_probe_read_user_str(&e->address, sizeof(e->address), p);
		e->port = port;
		e->retval = ret;
		e->sa_family = AF_INET6;
		
		bpf_ringbuf_submit(e, 0);
		
	}

	bpf_map_delete_elem(&connect_time, &id);
	bpf_map_delete_elem(&args_connect_map, &id);

	return 0;
}

struct conn_id_t
{
	u32 pid;
	int fd;
	__u64 timestamp;
};

struct conn_info_t
{
	struct conn_id_t conn_id;
	__s64 wr_bytes;
	__s64 rd_bytes;
	bool ishttp;
};

struct args_accept_t
{
	struct sockaddr_in *addr;
};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, struct args_accept_t);
} args_accept_map SEC(".maps");

//HTTP协议观测
SEC("tracepoint/syscalls/sys_enter_accept")
int tracepoint__syscalls_sys_enter_accept(struct trace_event_raw_sys_enter *ctx){
	u64 id = bpf_get_current_pid_tgid();

	struct args_accept_t accept_t = {};

	accept_t.addr = (struct sockaddr_in *)BPF_CORE_READ(ctx, args[1]);

	bpf_map_update_elem(&args_accept_map, &id, &accept_t, BPF_ANY);

	u64 ktime = bpf_ktime_get_ns();
	bpf_map_update_elem(&connect_time, &id, &ktime, BPF_ANY);

	return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int tracepoint__syscalls_sys_exit_accept(struct trace_event_raw_sys_exit *ctx){
	u64 id = bpf_get_current_pid_tgid();

	u64 *starttime = bpf_map_lookup_elem(&connect_time, &id);
	if(!starttime){
		return 0;
	}

	struct args_accept_t *args_accept = bpf_map_lookup_elem(&args_accept_map, &id);
	if(args_accept==NULL){
		return 0;
	}

	int ret = (int) BPF_CORE_READ(ctx, ret);

	struct conn_info_t conn_info = {};
	conn_info.conn_id.pid = id>>32;
	conn_info.conn_id.fd = - ret;

	conn_info.conn_id.timestamp= bpf_ktime_get_ns();

	struct socket_general_event_t event = {};
	event.time_ns = bpf_ktime_get_ns();
	event.pid = conn_info.conn_id.pid;
	event.fd = -ret;
	event.is_connection = true;

	bpf_perf_event_output()
}

SEC("kprobe/tcp_sendmsg")
int kprobe__tcp_sendmsg(tcp_sendmsg, struct sock *sk){
	u16 sk_family = 0;
	int ret = 0;
	if(ret = bpf_probe_read_kernel(&sk_family, sizeof(sk_family), &sk->sk_family)){
		return 0;
	}

	if(sk_family != AF_INET){
		
	}
}

SEC("kprobe/tcp_recvmsg")
int kprobe__


