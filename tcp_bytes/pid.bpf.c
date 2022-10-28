
#include "vmlinux.h"
#include "bpf/bpf_tracing.h"
#include "pid.h"
#include <bpf/bpf_helpers.h>

#define READ_KERN_V(ptr)                                   \
    ({                                                     \
        typeof(ptr) _val;                                  \
        __builtin_memset((void *)&_val, 0, sizeof(_val));  \
        bpf_probe_read((void *)&_val, sizeof(_val), &ptr); \
        _val;                                              \
    })
#define PID 50000

struct ipv4_value_t {
    u64 value;
    u64 saddr;
    u64 daddr;
    u32 lport;
    u32 dport;
};
struct ipv4_value_t *unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, struct ipv4_key_t);
    __type(value, struct ipv4_value_t);
} ipv4_send_bytes SEC(".maps");


/*探测内核中的 tcp_sendmsg 函数 */
SEC("kprobe/tcp_sendmsg")
int kprobe__tcp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *) PT_REGS_PARM1(ctx);
    size_t size = (size_t) PT_REGS_PARM3(ctx);

    /*获取当前进程的pid*/
    int pid = (int) bpf_get_current_pid_tgid();

    u16 family = READ_KERN_V(sk->__sk_common.skc_family);
    u64 saddr = READ_KERN_V(sk->__sk_common.skc_rcv_saddr);
    u64 daddr = READ_KERN_V(sk->__sk_common.skc_daddr);
    u32 lport = READ_KERN_V(sk->__sk_common.skc_num);
    u32 dport = READ_KERN_V(sk->__sk_common.skc_dport);

    /*判断是否是IPv4*/
    if (family == 2) {
        struct ipv4_key_t ipv4_key;
        ipv4_key.pid = pid;
        struct ipv4_value_t *val_p;
        u64 total = 0;
        val_p = bpf_map_lookup_elem(&ipv4_send_bytes, &ipv4_key);
        if (val_p) {
            val_p->value+=size;
            bpf_map_update_elem(&ipv4_send_bytes, &ipv4_key, val_p, BPF_ANY);
            total = val_p->value;
        } else {
            struct ipv4_value_t val={
                    .value=size,
                    .dport=dport,
                    .lport=lport,
                    .saddr=saddr,
                    .daddr=daddr,
            };
            bpf_map_update_elem(&ipv4_send_bytes, &ipv4_key, &val, BPF_ANY);
            total += val.value;
        }
        bpf_printk("pid:%d,send total:%d", pid, total);


    }
    return 0;
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct ipv4_key_t);
    __type(value, u64);
} ipv4_recv_bytes SEC(".maps");

////BPF_MAP_TYPE_HASH(ipv4_recv_bytes, struct ipv4_key_t);
///*探测内核中的 tcp_cleanup_rbuf 函数 */
SEC("kprobe/tcp_cleanup_rbuf")
int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *) PT_REGS_PARM1(ctx);
    size_t bytes_received = (int32_t) PT_REGS_PARM2(ctx);
    /*获取当前进程的pid*/
    int pid = (int) bpf_get_current_pid_tgid();
    /*此部分在python里处理，用于替换特定功能的c语句*/
    u16 family = READ_KERN_V(sk->__sk_common.skc_family);
    /*判断是否是IPv4*/
    u64 total = 0;

    if (family == 2) {
        /*将当前进程的pid放入ipv4_key结构体中
          作为ipv4_send_bytes哈希表的关键字*/
        struct ipv4_key_t ipv4_key;
        ipv4_key.pid = pid;
        u64 *val = NULL;
        val = bpf_map_lookup_elem(&ipv4_recv_bytes, &ipv4_key);
        if (val != NULL && *val) {
            *val += bytes_received;
            total += *val;
            bpf_map_update_elem(&ipv4_recv_bytes, &ipv4_key, val, BPF_ANY);
        } else {
            val = (u64 *) &bytes_received;
            total += *val;
            bpf_map_update_elem(&ipv4_recv_bytes, &ipv4_key, val, BPF_ANY);
        }
        bpf_printk("pid %d ,receive %llu", ipv4_key.pid, total);
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
