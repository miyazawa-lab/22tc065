//SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <scx/common.bpf.h>



char _license[] SEC("license") "GPL";

const int[] rising = {67,72,77};
const int[] decent = {64,69,74};

int stage = 0;

struct temp_rec {
    int id;
    int temp;

};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct metric_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} metrics SEC(".maps");

static __always_inline void classify_task(struct task_struct *p, __u64 *deadline_ns, int *cls)
{
    if(&deadline <= 2000000)
	&cls = 0;
    else if(&deadline <= 15000000)
	&cls = 1;
    else
	&cls = 2;
}

/*select_cpu → enqueue → dispatch
select_cpuで直入れしたらenqueueは飛ばされる
*/
s32 BPF_STRUCT_OPS(prototype_select_cpu, struct *p, s32 prev_cpu, u64 wake_flags)
{
	u32 cpu;
	cpu = decide_cpu(p, prev_cpu);
	if(cpu >= 0) {
		if(!(p->dl_throttled == 1 && p->dl_non_contending == 1)) {
			if(realtive_time >= 0 && relative_time <= border) {
				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, /*SCX_SLICE_DEF*/, enq_flags);
				return cpu;
			}
		}
	}
	return prev_cpu
    classify_task(p );
}

void BPF_STRUCT_OPS(prototype_enqueue, struct task_struct *p, u64 enq_flags)
{
	u32 relative_time = p->dl.runtime;
	u32 absolute_time = p->dl.deadline;
	const u64  border = 1000000ULL;
	const u64  now_border = 1000000ULL;
	const u64  later_border = 1000000ULL;
	if(!(p->dl_throttled == 1 && p->dl_non_contending == 1)) {
		if(relative_time <= new_border) {
			scx_bpf_dsq_insert(p, FAST, /*SCX_SLICE_DEF*/, enq_flags);
			scx_bpf_dsq_insert(p, NORMAL, /*SCX_SLICE_DEF*/, enq_flags);
			return;
		}
		
	}
	
		
}

void BPF_STRUCT_OPS(prototype_dequeue, struct task_struct *p, u64 deq_flags)
{

}


void BPF_STRUCT_OPS(prototype_dispatch, s32 cpu, struct task_struct *prev)
{

}

struct trace_event_raw_thermal_temperature *ctx;

SEC("tracepoint/therm/thermal_temperature")
int tp_thermal(ctx)
{
    struct temp_rec tp;
    tp.id   = ctx->id;
    tp.temp = ctx->temp;
    int prev_tmp;
    if(tp.id > rising[0]) {
	stage = 3;
    } else if(tp.id > rising[1]){
        stage = 2;
    } else if(tp.id > rising[2]){
        stage = 1;
    }
    return 0;
}


s32 BPF_STRUCT_OPS_SLEEPABLE(prototype_init)
{
    scx_bpf_create_dsq(EMERGENCY, -1);
    scx_bpf_create_dsq(FAST, -1);
    scx_bpf_create_dsq(ALWAYS, -1);
    scx_bpf_create_dsq(NORMAL, -1);
    scx_bpf_create_dsq(LATER, -1);
    scx_bpf_create_dsq(GOAWAY, -1);

}
void BPF_STRUCT_OPS(prototype_exit, struct scx_exit_info *ei)
{
    scx_bpf_destroy_dsq(FALLBACK_DSQ_ID);
}

SCX_OPS_DEFINE(prototype_ops,
. = (void *)prototype_,

.name = "scx_prototype");
