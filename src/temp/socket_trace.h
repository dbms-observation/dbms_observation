#ifndef __SYSCALL_TRACER_H
#define __SYSCALL_TRACER_H

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

#define MAX_MSG_SIZE 256

struct syscall_connect_event {
	int sa_family;
	long retval;
	//char ipv4address[INET_ADDRSTRLEN];
	char address[INET6_ADDRSTRLEN];
	int port;
	int dur_us;
};

struct socket_general_event_t
{
	unsigned long long time_ns;
	unsigned int pid;
	int fd;
	bool is_connection;
	unsigned int msg_size;
	unsigned long long pos;
	char msg[MAX_MSG_SIZE];
};

#endif /* __SYSCALL_TRACER_H */