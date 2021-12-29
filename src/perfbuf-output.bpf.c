// 代码来源：https://github.com/anakryiko/bpf-ringbuf-examples

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/**
 * BPF perfbuf map 
 * 不需要定义max_entries属性，因为 libbpf 会处理它并根据系统上可用的 CPU 数量自动调整它的大小。
 * 每个 CPU 缓冲区的大小是与用户空间分开指定的
*/
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} pb SEC(".maps");

/**
 * 将文件名的最大捕获大小设置为 512 字节。
 * 无法在程序中使用变量存储，因为堆栈大小限制
 * 所以，使用一个map存储。map选择时，选择PERCPU
*/
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct event);
} heap SEC(".maps");

/**
 * 静态追踪点，/sys/kernel/debug/tracing/events/sched/sched_process_exec
*/
SEC("tp/sched/sched_process_exec")
int haddle_exec(struct trace_event_raw_sched_process_exec *ctx){
	unsigned fname_off = ctx->__data_loc_filename & 0xFFFF;
	struct event *e;
	int zero = 0;

	// heap map 的 第一个value的地址
	e = bpf_map_lookup_elem(&heap, &zero);
	if(!e)
		return 0;
	
	// 通过帮助函数，获取pid，命令名，文件名
	e->pid = bpf_get_current_pid_tgid()>>32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

	bpf_perf_event_output(ctx,&pb,BPF_F_CURRENT_CPU,e,sizeof(*e));
	return 0;
}