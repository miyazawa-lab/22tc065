//SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <scx/common.bpf.h>



char _license[] SEC("license") = "GPL";

const __s32 ALLOWED_CPUS[3] = {0, 1, 2};

#define FAST 0x1000ULL
//#define DSQ_ALWAYS 1002ULL
#define NORMAL 0x2000ULL
//#define DSQ_LATER 1004ULL

#define SLACK_NS 500000ULL
#define DL_SMALL_NS 1000000ULL
#define CFS_UTIL_SMALL 128   

#define CPU_NUM 4

int stage = 0;

enum { STG_COOL, STG_WARM, STG_HOT, STG_NR };

struct ratio {
	u32 now, later;
};
/*
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct metric_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} metrics SEC(".maps");
*/
const volatile struct ratio g_ratio[STG_NR] = {
    [STG_COOL] = {5, 3}, [STG_WARM] = {7, 3}, [STG_HOT] = {3, 1},
};

volatile __u32 g_rr_cpu;
/*
select_cpu → enqueue → dispatch
select_cpuで直入れしたらenqueueは飛ばされる
*/
const volatile __s32 rising_degC[4] = { 0, 67, 72, 77 };
const volatile __s32 falling_degC[4] = { 0, 64, 69, 74 };

const volatile __s32 g_filter_tz_id = -1;

volatile __u32 g_stage = STG_COOL;

static __always_inline __u32 next_stage_hysteresis(__u32 cur, int temp_mC, const __s32 *rC, const __s32 *dC)
{
    const int r_warm_mC = rC[1] * 1000;
    const int r_hot_mC  = rC[2] * 1000;
    const int r_nr_mC   = rC[3] * 1000;

    const int d_hot_mC  = dC[3] * 1000;
    const int d_warm_mC = dC[2] * 1000;
    const int d_cool_mC = dC[1] * 1000;

    switch (cur) {
    case STG_COOL:
        return (temp_mC >= r_warm_mC) ? STG_WARM : STG_COOL;

    case STG_WARM:
        if (temp_mC >= r_hot_mC)
			return STG_HOT;
        if (temp_mC <  d_cool_mC)
			return STG_COOL;
        return STG_WARM;

    case STG_HOT:
        if (temp_mC >= r_nr_mC)
			return STG_NR;
        if (temp_mC <  d_warm_mC)
			return STG_WARM;
        return STG_HOT;

    case STG_NR:
    default:
        return (temp_mC < d_hot_mC) ? STG_HOT : STG_NR;
    }
}

static __always_inline bool determine_tof(const struct task_struct *p)
{
	if ((p->policy != SCHED_DEADLINE) || p->dl_throttled == 1 || p->dl_non_contending == 1)
		return false;
    if ((s64)p->dl.runtime <= 0)
        return false;
	if (p->dl.dl_boosted)
        return true;
	s64 laxity = (s64)p->dl.deadline - (s64)bpf_ktime_get_ns() - (s64)p->dl.runtime;
	//return p->policy == SCHED_DEADLINE && p->dl.pi_se && (p->dl.pi_se != &p->dl);
    return laxity > 0;
}

static __always_inline bool cpu_online(s32 cpu)
{
    const struct cpumask *online = scx_bpf_get_online_cpumask();
    return online && cpu >= 0 && bpf_cpumask_test_cpu(cpu, online);
}

static __always_inline s32 pick_idle_cpu012(void)
{
    const struct cpumask *idle = scx_bpf_get_idle_cpumask();
    if (!idle) 
		return -1;
    #pragma clang loop unroll(full)
    for (int i = 0; i < 3; i++) {
        s32 cpu = ALLOWED_CPUS[i];
        if (bpf_cpumask_test_cpu(cpu, idle))
            return cpu;
    }
    return -1;
}


static __always_inline bool determine_sz(const struct task_struct *p)
{
    if (is_sched_dl(p))
        return (u64)p->dl.runtime <= (u64)DL_SMALL_NS;
    return p->se.avg.util_avg <= CFS_UTIL_SMALL;
}

static __always_inline s32 pick_target_cpu(void)
{
    const struct cpumask *idle = scx_bpf_get_idle_cpumask();
    if (idle) {
        for (int i = 0; i < 4; i++) {
            s32 cand = (g_rr_cpu + i) & 3;
            if (bpf_cpumask_test_cpu(cand, idle))
                return cand;
        }
    }
    s32 best = -1; __u64 best_depth = ~0ULL;
    for (int cpu = 0; cpu < 4; cpu++) {
        __u64 depth = scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu);
        if (depth < best_depth) { 
			best_depth = depth;
			best = cpu;
		}
    }
    g_rr_cpu = best + 1;
    return best >= 0 ? (best & 3) : bpf_get_smp_processor_id();
}

static __always_inline bool move_one(__u64 src_dsq, s32 target_cpu)
{
    s32 this_cpu = bpf_get_smp_processor_id();

    if (target_cpu == this_cpu)
        return scx_bpf_dsq_move_to_local(src_dsq);

    struct bpf_iter_scx_dsq it;
    if (bpf_iter_scx_dsq_new(&it, src_dsq, 0))
        return false;

    struct task_struct *p;
    bool ok = false;
    while ((p = bpf_iter_scx_dsq_next(&it))) {
        ok = __COMPAT_scx_bpf_dsq_move(&it, p, SCX_DSQ_LOCAL_ON | target_cpu, 0);
        if (ok) break;
    }
    bpf_iter_scx_dsq_destroy(&it);
    return ok;
}

static __always_inline bool dispatch_one_weighted(void)
{
    static __u32 credit_now, credit_later;
    const struct ratio r = g_ratio[g_stage];

    if (credit_now == 0 && credit_later == 0) {
        credit_now = r.now; 
		credit_later = r.later;
	}
	
    bool try_now = (credit_now >= credit_later);

    for (int turn = 0; turn < 2; turn++) {
        __u64 dsq = try_now ? FAST : NORMAL;
        s32 target = pick_target_cpu();
        if (move_one(dsq, target)) {
            if (try_now) 
				credit_now--; 
			else 
				credit_later--;
            g_rr_cpu++;
            return true;
        }
        try_now = !try_now;
    }
    return false;
}

s32 BPF_STRUCT_OPS(prototype_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	u32 cpu;
	cpu = pick_idle_cpu012();
	if(cpu >= 0) {
		if(determine_tof(p)) {
		s64 laxity = (s64)p->dl.deadline - (s64)bpf_ktime_get_ns()- (s64)p->dl.runtime;
			if(SLACK_NS - laxity> 0) {
				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, /*SCX_SLICE_DEF*/, 0);
				return cpu;
			}
		}
	}
	return prev_cpu;
}

void BPF_STRUCT_OPS(prototype_enqueue, struct task_struct *p, u64 enq_flags)
{
	const u64  border = 1000000ULL;
	const u64  now_border = 1000000ULL;
	const u64  later_border = 1000000ULL;
	if(determine_tof(p)) {
		if(p->dl.runtime <= now_border) 
			scx_bpf_dsq_insert(p, FAST, /*SCX_SLICE_DEF*/, 0);
		else
			scx_bpf_dsq_insert_vtime(p, NORMAL, /*SCX_SLICE_DEF*/, 0);
	}
}

void BPF_STRUCT_OPS(prototype_dequeue, struct task_struct *p, u64 deq_flags)
{

}

void BPF_STRUCT_OPS(prototype_dispatch, s32 cpu, struct task_struct *prev)
{
	__u32 slots = scx_bpf_dispatch_nr_slots();
    for (__u32 i = 0; i < slots; i++) {
        if (!dispatch_one_weighted())
            break;
    }	
}



SEC("tracepoint/thermal/thermal_temperature")
int tp_thermal(struct trace_event_raw_thermal_temperature *ctx)
{
    if (g_filter_tz_id >= 0 && ctx->id != g_filter_tz_id)
        return 0;

    const int temp_mC = ctx->temp;

    __u32 cur = g_stage;
    __u32 nxt = next_stage_hysteresis(cur, temp_mC, rising_degC, falling_degC);
    if (nxt != cur)
        g_stage = nxt;

    return 0;
}


s32 BPF_STRUCT_OPS_SLEEPABLE(prototype_init)
{
    scx_bpf_create_dsq(FAST, -1);
    scx_bpf_create_dsq(NORMAL, -1);
    //scx_bpf_create_dsq(GOAWAY, -1);
    //scx_bpf_create_dsq(EMERGENCY, -1);
    //scx_bpf_create_dsq(ALWAYS, -1);
    //scx_bpf_create_dsq(LATER, -1);
	return 0;
}
void BPF_STRUCT_OPS(prototype_exit, struct scx_exit_info *ei)
{
    scx_bpf_destroy_dsq(FAST);
    scx_bpf_destroy_dsq(NORMAL);
    //scx_bpf_destroy_dsq(GOAWAY);
}

s32 BPF_STRUCT_OPS(prototype_init_task, struct task_struct *p, struct scx_init_task_args *args) 
{
	return 0;
}

SEC(".struct_ops") struct sched_ext_ops prototype_ops = {
.select_cpu	= (void *)prototype_select_cpu,
.enqueue 	= (void *)prototype_enqueue,
.dispatch 	= (void *)prototype_dispatch,
.dequeue 	= (void *)prototype_dequeue,
.init 		= (void *)prototype_init,
.init_task 	= (void *)prototype_init_task,
.exit 		= (void *)prototype_exit,
.name 		= "scx_prototype"};
