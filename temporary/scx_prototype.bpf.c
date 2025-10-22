//SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <scx/common.bpf.h>



char _license[] SEC("license") "GPL";

const int[] rising = {67,72,77};
const int[] decent = {64,69,74};


#define DSQ_FAST 1001ULL
#define DSQ_ALWAYS 1002ULL
#define DSQ_NORMAL 1003ULL
#define DSQ_LATER 1004ULL

#define SLACK_NS 500000ULL
#define DL_SMALL_NS 1000000ULL
#define CFS_UTIL_SMALL 128   

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

static __always_inline bool determine_tof(const struct task_struct *p)
{
	if ((p->policy == SCHED_DEADLINE) || p->dl_throttled == 1 || p->dl_non_contending == 1)
		return false;
    if ((s64)p->dl.runtime <= 0)
        return false;
	if (p->dl.dl_boosted)
        return true;
	s64 laxity = (s64)p->dl.deadline - (s64)scx_bpf_now() - (s64)p->dl.runtime;
	//return p->policy == SCHED_DEADLINE && p->dl.pi_se && (p->dl.pi_se != &p->dl);
    return laxity > 0;
}

static __always_inline bool determine_sz(const struct task_struct *p)
{
    if (is_sched_dl(p))
        return (u64)p->dl.runtime <= (u64)DL_SMALL_NS;
    return p->se.avg.util_avg <= CFS_UTIL_SMALL;
}

s32 BPF_STRUCT_OPS(prototype_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	u32 cpu;
	cpu = decide_cpu(p, prev_cpu);
	if(cpu >= 0) {
		if(determine_tof(p)) {
		s64 laxity = (s64)p->dl.deadline - (s64)scx_bpf_now() - (s64)p->dl.runtime;
			if(laxity - SLACK_NS > 0) {
				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, /*SCX_SLICE_DEF*/, enq_flags);
				return cpu;
			}
		}
	}
	return prev_cpu
}

void BPF_STRUCT_OPS(prototype_enqueue, struct task_struct *p, u64 enq_flags)
{
	u32 relative_time = p->dl.runtime;
	u32 absolute_time = p->dl.deadline;
	const u64  border = 1000000ULL;
	const u64  now_border = 1000000ULL;
	const u64  later_border = 1000000ULL;
	if(determine_tof(p)) {
		if(relative_time <= new_border) {
			scx_bpf_dsq_insert(p, FAST, /*SCX_SLICE_DEF*/, enq_flags);
			scx_bpf_dsq_insert(p, ALWAYS, /*SCX_SLICE_DEF*/, enq_flags);
			return;
		}	
	}
	scx_bpf_dsq_insert(p, NORMAL, /*SCX_SLICE_DEF*/, enq_flags);
	scx_bpf_dsq_insert(p, LATER, /*SCX_SLICE_DEF*/, enq_flags);
	
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
