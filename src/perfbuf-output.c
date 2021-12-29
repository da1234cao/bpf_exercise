#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "perfbuf-output.skel.h"
#include "common.h"


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

static volatile bool exiting = false;
static void sig_handler(int sig){
	exiting = true;
}

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


int main(int argc, char **argv){
	struct perf_buffer *pb = NULL;
	struct perf_buffer_opts pb_opts = {};
	struct perfbuf_output_bpf *skel;
	int err;

	/**
	 * libbpf_set_print()为所有 libbpf 日志提供自定义回调。
	 * 这非常有用，尤其是在活跃开发期间，因为它允许捕获有用的 libbpf 调试日志。
	 * 默认情况下，如果出现问题，libbpf 将仅记录错误级别的消息。
	 * 但是，调试日志有助于获得有关正在发生的事情的额外上下文并更快地调试问题。
	*/
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to create BPF maps */
	bump_memlock_rlimit();

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

cleanup:
	perf_buffer__free(pb);
	perfbuf_output_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}