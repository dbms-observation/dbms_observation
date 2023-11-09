#include <argp.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>
// #include "btf_helpers.h"
#include "httptrace.h"
#include "httptrace.skel.h"
// #include "trace_helpers.h"

#define PERF_BUFFER_PAGES 16
#define PERF_POLL_TIMEOUT_MS 100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

static bool emit_timestamp = false;
static short target_family = 0;
static char* target_sports = NULL;
static char* target_dports = NULL;
static bool wide_output = false;
static bool verbose = false;
// static const char* tcp_states[] = {
//     [1] = "ESTABLISHED", [2] = "SYN_SENT",   [3] = "SYN_RECV",
//     [4] = "FIN_WAIT1",   [5] = "FIN_WAIT2",  [6] = "TIME_WAIT",
//     [7] = "CLOSE",       [8] = "CLOSE_WAIT", [9] = "LAST_ACK",
//     [10] = "LISTEN",     [11] = "CLOSING",   [12] = "NEW_SYN_RECV",
//     [13] = "UNKNOWN",
// };

const char* argp_program_version = "tcpstates 1.0";
const char* argp_program_bug_address =
    "https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
    "Trace TCP session state changes and durations.\n"
    "\n"
    "USAGE: tcpstates [-4] [-6] [-T] [-L lport] [-D dport]\n"
    "\n"
    "EXAMPLES:\n"
    "    tcpstates                  # trace all TCP state changes\n"
    "    tcpstates -T               # include timestamps\n"
    "    tcpstates -L 80            # only trace local port 80\n"
    "    tcpstates -D 80            # only trace remote port 80\n";

static const struct argp_option opts[] = {
    {"verbose", 'v', NULL, 0, "Verbose debug output"},
    {"timestamp", 'T', NULL, 0, "Include timestamp on output"},
    {"ipv4", '4', NULL, 0, "Trace IPv4 family only"},
    {"ipv6", '6', NULL, 0, "Trace IPv6 family only"},
    {"wide", 'w', NULL, 0, "Wide column output (fits IPv6 addresses)"},
    {"localport", 'L', "LPORT", 0,
     "Comma-separated list of local ports to trace."},
    {"remoteport", 'D', "DPORT", 0,
     "Comma-separated list of remote ports to trace."},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
    {},
};

static error_t parse_arg(int key, char* arg, struct argp_state* state) {
    long port_num;
    char* port;

    switch (key) {
        case 'v':
            verbose = true;
            break;
        case 'T':
            emit_timestamp = true;
            break;
        case '4':
            target_family = AF_INET;
            break;
        case '6':
            target_family = AF_INET6;
            break;
        case 'w':
            wide_output = true;
            break;
        case 'L':
            if (!arg) {
                warn("No ports specified\n");
                argp_usage(state);
            }
            target_sports = strdup(arg);
            port = strtok(arg, ",");
            while (port) {
                port_num = strtol(port, NULL, 10);
                if (errno || port_num <= 0 || port_num > 65536) {
                    warn("Invalid ports: %s\n", arg);
                    argp_usage(state);
                }
                port = strtok(NULL, ",");
            }
            break;
        case 'D':
            if (!arg) {
                warn("No ports specified\n");
                argp_usage(state);
            }
            target_dports = strdup(arg);
            port = strtok(arg, ",");
            while (port) {
                port_num = strtol(port, NULL, 10);
                if (errno || port_num <= 0 || port_num > 65536) {
                    warn("Invalid ports: %s\n", arg);
                    argp_usage(state);
                }
                port = strtok(NULL, ",");
            }
            break;
        case 'h':
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char* format,
                           va_list args) {
    if (level == LIBBPF_DEBUG && !verbose)
        return 0;

    return vfprintf(stderr, format, args);
}

static void sig_int(int signo) {
    exiting = 1;
}

static void handle_event(void* ctx, int cpu, void* data, __u32 data_sz) {
    struct event* e = data;

    if(e->type==1){
        printf("sendmsg %s ,data:%s ,dur:%lld \n",
            e->sendmsg.comm, e->sendmsg.data, e->sendmsg.dur_us);
    }else{
        printf("error");
    }
}

static void handle_lost_events(void* ctx, int cpu, __u64 lost_cnt) {
    warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int main(int argc, char** argv) {
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
        .doc = argp_program_doc,
    };
    struct perf_buffer* pb = NULL;
    struct httptrace_bpf* obj;
    int err, port_map_fd;
    //short port_num;
    //char* port;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    obj = httptrace_bpf__open_opts(&open_opts);
    if (!obj) {
        warn("failed to open BPF object\n");
        return 1;
    }

    err = httptrace_bpf__load(obj);
    if (err) {
        warn("failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    err = httptrace_bpf__attach(obj);
    if (err) {
        warn("failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
                          handle_event, handle_lost_events, NULL, NULL);
    if (!pb) {
        err = -errno;
        warn("failed to open perf buffer: %d\n", err);
        goto cleanup;
    }

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        warn("can't set signal handler: %s\n", strerror(errno));
        err = 1;
        goto cleanup;
    }

    // if (emit_timestamp)
    //     printf("%-8s ", "TIME(s)");
    // if (wide_output)
    //     printf(
    //         "%-16s %-7s %-16s %-2s %-26s %-5s %-26s %-5s %-11s -> %-11s %s\n",
    //         "SKADDR", "PID", "COMM", "IP", "LADDR", "LPORT", "RADDR", "RPORT",
    //         "OLDSTATE", "NEWSTATE", "MS");
    // else
    //     printf("%-16s %-7s %-10s %-15s %-5s %-15s %-5s %-11s -> %-11s %s\n",
    //            "SKADDR", "PID", "COMM", "LADDR", "LPORT", "RADDR", "RPORT",
    //            "OLDSTATE", "NEWSTATE", "MS");

    while (!exiting) {
        err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
        if (err < 0 && err != -EINTR) {
            warn("error polling perf buffer: %s\n", strerror(-err));
            goto cleanup;
        }
        /* reset err to return 0 if exiting */
        err = 0;
    }

cleanup:
    perf_buffer__free(pb);
    httptrace_bpf__destroy(obj);

    return err != 0;
}