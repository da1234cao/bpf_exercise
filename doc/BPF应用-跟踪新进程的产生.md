[toc]

# 前言

**目标**：使用BPF技术，跟踪系统中新进程的产生。对于每个系统调用函数exec()，将进程ID，进程名称和可执行文件路径捕获并发送到用户空间进行处理。

**实现要点**：BPF程序的附加位置，BPF程序使用的上下文结构，map类型的选择，该类型map的相关操作，`libbpf-bootstrap`中`BPF skeleton`的使用和BPF程序的生命周期。

* 程序的追踪点(BPF程序的附加位置)：`sched:sched_process_exec`。
* BPF程序使用的上下文结构：`/sys/kernel/debug/tracing/events/sched/sched_process_exec/format`。
* 使用的map类型：选择perf buffer从内核向用户空间发送数据，所以使用`BPF_MAP_TYPE_PERF_EVENT_ARRAY`型map。
* 使用 `libbpf-bootstrap` 构建 BPF 应用程序。

<font color=red>下文内容和代码来源于</font>：

[BCC to libbpf conversion guide](https://nakryiko.com/posts/bcc-to-libbpf-howto-guide/#bpf-skeleton-and-bpf-app-lifecycle) --> [BCC 到 libbpf 的转换指南【译】](https://www.ebpf.top/post/bcc-to-libbpf-guid/)

[Building BPF applications with libbpf-bootstrap](https://nakryiko.com/posts/libbpf-bootstrap/#bootstrap-app) 

[BPF ring buffer](https://nakryiko.com/posts/bpf-ringbuf/) --> [BPF 环形缓冲区【译】](https://www.ebpf.top/post/bpf_ring_buffer/)

---

# 示例代码

**完整代码地址**：[perfbuf-output.c](https://github.com/da1234cao/bpf_exercise)

```c
✗ git clone git@github.com:da1234cao/bpf_exercise.git
✗ git submodule update --init --recursive
✗ cd bpf_exercise/src
✗ make
```

该程序将跟踪新进程产生的所有execs进程。 对于每个系统调用函数exec()，进程ID（pid），进程名称（comm）和可执行文件路径（filename）被捕获到一个样本中，并发送到用户空间进行处理。这里，我们仅是调用printf()，将所有内容打印到标准输出中。（记住要使用sudo运行示例）：

```shell
✗ sudo ./perfbuf-output 
TIME     EVENT PID     COMM             FILENAME
20:03:03 EXEC  93759   sh               /bin/sh
20:03:03 EXEC  93760   which            /usr/bin/which
20:03:03 EXEC  93761   sh               /bin/sh
20:03:03 EXEC  93762   ps               /usr/bin/ps
20:03:03 EXEC  93763   sh               /bin/sh
20:03:03 EXEC  93764   cpuUsage.sh      /usr/share/code/resources/app/out/vs/base/node/cpuUsage.sh
20:03:03 EXEC  93765   sed              /usr/bin/sed
20:03:03 EXEC  93766   cat              /usr/bin/cat
^C
```

下面是样本数据的C结构定义。此数据结构用于BPF程序发送的数据，同时用于程序的用户空间部分使用。

```c
#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 512

/* definition of a sample sent to user-space from BPF program */
struct event {
	int pid;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
};
```



---

## sched_process_exec处的BPF程序抓取数据发送到perf buffer

首先，头文件包括内核的<linux / bpf.h>有一些基本 BPF 定义，libbpf <bpf / bpf_helpers.h>定义了BPF帮助器。“ common.h”定义了应用程序类型，该程序类型可在BPF程序和用户空间程序代码之间共享。这里，我们还指定程序遵循GPL-2.0/BSD-3双重许可：

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
```

接下来，我们将定义BPF perfbuf为BPF_MAP_TYPE_PERF_EVENT_ARRAY映射。无需定义 max_entries 属性，因为 libbpf 会处理该属性，将其自动调整为系统上可用CPU数量。每个CPU缓冲区的大小不与用户空间共享，需要单独定义，接下来我们将会介绍。

```c
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
```

如下图所示，数据结构event定义在[common.h](https://github.com/anakryiko/bpf-ringbuf-examples/blob/main/src/common.h#L6-20)中，其中我们将filename的最大值设为512字节，所以样本占用字节大于 512字节，所以无法在堆栈上保存。 因此，我们将使用单元素单CPU数组作为临时存储：

```c
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
```

现在，我们将定义BPF程序，指定将其附加到sched:sched_process_exec上，该跟踪点将在每个成功调用系统调用exec()上触发。<font color=red>struct trace_event_raw_sched_process_exec也定义在common.h中，仅是从Linux源代码的复制/粘贴。该数据结构定义了该跟踪点的输入数据</font>。（我花了挺久时间，没有在内核中找见这个结构：[sched_process_exec](https://elixir.bootlin.com/linux/latest/source/include/trace/events/sched.h#L397)、[Using the Linux Kernel Tracepoints](https://www.kernel.org/doc/html/latest/trace/tracepoints.html)）

```c
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
```

BPF程序逻辑非常简单。为样本获取一个临时存储，并用跟踪点上下文中的数据填充它。完成后，它将通过调用 bpf_perf_event_output() 将发送样本到BPF perfbuf。该 API 会在当前 CPU 的 perf 缓冲区中为数据结构 event 预留空间，将数据从 e 的sizeof(* e) 字节复制到该预留空间，完成后将向用户空间发出新数据可用的信号。此时，epoll 子系统将唤醒用户空间处理程序，并将指针传递到该数据副本进行处理。



---

## BPF skeleton and BPF app lifecycle

在开始看用户空间代码之前，我们需要先了解[BPF skeleton](https://nakryiko.com/posts/bcc-to-libbpf-howto-guide/#bpf-skeleton-and-bpf-app-lifecycle)。

使用 BPF 框架（以及一般的 libbpf API）的详细解释超出了本文档的范围，现有的[内核自测](https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/tree/tools/testing/selftests/bpf)和 BCC [libbpf-tools 示例](https://github.com/iovisor/bcc/tree/master/libbpf-tools)可能是学习的最佳方式。查看 [runqslower](https://github.com/iovisor/bcc/blob/master/libbpf-tools/runqslower.c) 示例也可作为一个使用 skeleton 的简单但真实的工具。

尽管如此，解释每个 BPF 应用程序所涉及的 libbpf 概念和对应的阶段还是很有用的。BPF 应用程序由一组协作或完全独立的 BPF 程序以及 BPF map 和全局变量组成，map 及全局变量可在所有 BPF 程序之间共享（允许它们在一组公共数据上进行协作）。BPF map 和全局变量也可以从用户空间访问（我们可以将应用程序的用户空间部分称为 ”控制程序” ），其允许控制程序获取或设置任何必要的额外数据。BPF 程序通常会经历以下阶段：

- **打开阶段**。解析 BPF 目标文件：发现 BPF map 、BPF 程序和全局变量，但此时尚未创建。在打开 BPF 程序后，可以在创建和加载所有实体之前进行其他调整（如有必要：设置 BPF 程序类型；预先设置全局变量的初始值等）。
- **加载阶段**。创建 BPF map ，解析各种重定位，将 BPF 程序加载到内核中并进行验证。此时，BPF 程序的所有部分都已验证并存在于内核中，但尚未执行任何 BPF 程序。在加载阶段之后，可在不与 BPF 程序代码执行竞争的情况下设置初始 BPF map 状态。
- **附着阶段**。这是 BPF 程序附加到各种 BPF 挂钩点的阶段（挂载点包括：tracepoints、kprobes、cgroup hook、网络数据包处理管道等等）。这是 BPF 开始执行功能、读取/更新 BPF map 和全局变量的阶段。
- **拆除阶段**。BPF 程序从内核中分离并卸载。BPF map 被销毁，BPF 程序使用的所有资源都被释放。

生成的 BPF skeleton 有相应的函数来实现每个阶段的触发：

- `<name>_bpf__open()` – 创建并打开 BPF 应用程序；
- `<name>_bpf__load()` – 实例化、加载和验证 BPF 应用程序部分；
- `<name>_bpf__attach()` – 附加所有可自动附加的 BPF 程序（它是可选的，你可以通过直接使用 libbpf API 获得更多控制）；
- `<name>_bpf__destroy()` – 分离所有BPF 程序并释放所有使用的资源；



---

## 用户空间读取perf buffer

完成最小的初始设置后，例如：设置 libbpf 日志处理程序，中断处理程序，提高 BPF 系统的 RLIMIT_MEMLOCK 限制，它只会打开并加载BPF框架。

```c
int libbpf_print_fn(enum libbpf_print_level level,const char *format, va_list args){
	/* Ignore debug-level libbpf logs */
	if(level > LIBBPF_INFO)
		return 0;
	return vfprintf(stderr,format,args);
}

void bump_memlock_rlimit(void){
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if(setrlimit(RLIMIT_MEMLOCK, &rlim_new)){
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

	/* Clean handling of Ctrl-C */
	signal(SIGINT,sig_handler);
	signal(SIGTERM,sig_handler);

	/* Load and verify BPF application */
	skel = perfbuf_output_bpf__open_and_load();
	if(!skel){
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint */
	err = perfbuf_output_bpf__attach(skel);
	if(err){
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
```

如果一切成功，我们将使用 libbpf 用户空间的 perf_buffer__new() API 创建一个 perf 缓冲区使用实例。这里，我们指定每个CPU缓冲区为 32 KB，8X4096，即 8页，每4096字节。对于提交样本，libbpf将调用 handle_event() 回调，该回调仅调用 printf() 打印数据：

```c
void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz){
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8s %-5s %-7d %-16s %s\n", ts, "EXEC", e->pid, e->comm, e->filename);
}

	/* if specified, sample_cb is called for each sample */
	pb_opts.sample_cb = handle_event;

	/* Set up ring buffer polling */
	// libbpf v0.7+ 使用perf_buffer__new_deprecated替代原来的perf_buffer__new
	// 新的perf_buffer__new，有六个参数
	// https://stackoverflow.com/questions/70417623/i-have-a-function-call-in-one-program-and-this-function-is-depreciated-is-there
	pb = perf_buffer__new_deprecated(bpf_map__fd(skel->maps.pb),8/* 32KB per CPU */, &pb_opts);
	if(libbpf_get_error(pb)){
		err = -1;
		fprintf(stderr,"Failed to create perf buffer\n");
		goto cleanup;
	}
```

最后一步是只要有可用数据就持续打印数据，直到需要退出为止（例如，如果用户按Ctrl-C）：

```c
	/* Process events */
	printf("%-8s %-5s %-7s %-16s %s\n","TIME", "EVENT", "PID", "COMM", "FILENAME");
	while(!exiting){
		err = perf_buffer__poll(pb,100/* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if(err < 0){
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}
```



---

# 其他链接

[Debian下libbpf编译失败提示<asm/types.h>文件不存在解决方法](https://ghl.name/archives/how-to-fix-asm-types-h-no-found.html)

[I have a function call in one program and this function is depreciated.Is there any newer version that I can use in my code | perf_buffer__new in ebpf](https://stackoverflow.com/questions/70417623/i-have-a-function-call-in-one-program-and-this-function-is-depreciated-is-there)