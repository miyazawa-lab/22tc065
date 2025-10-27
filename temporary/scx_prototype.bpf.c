//SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <scx/common.bpf.h>



char _license[] SEC("license") "GPL";

const int[] rising = {67,72,77};
const int[] decent = {64,69,74};

const　s32 aloowed[3] = {0, 1, 2};

#define DSQ_FAST 1001ULL
#define DSQ_ALWAYS 1002ULL
#define DSQ_NORMAL 1003ULL
#define DSQ_LATER 1004ULL

#define SLACK_NS 500000ULL
#define DL_SMALL_NS 1000000ULL
#define CFS_UTIL_SMALL 128   

#define CPU_NUM 4

int stage = 0;

enum { STG_COOL, STG_WARM, STG_HOT, STG_NR };

struct temp_rec {
    int id;
    int temp;

};

struct ratio {
	u32 now, later;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct metric_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} metrics SEC(".maps");

const volatile struct ratio g_ratio[STG_NR] = {
    [STG_COOL] = {5, 3}, [STG_WARM] = {7, 3}, [STG_HOT] = {3, 1},
};

const volatile __u64 NOW_DSQ = 0x1000ULL;
const volatile __u64 LATER_DSQ = 0x2000ULL;

volatile __u32 g_rr_cpu;

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
        s32 cpu = ALLOWED[i];
        if (bpf_cpumask_test_cpu(cpu, idle) && cpu_online(cpu))
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

s32 BPF_STRUCT_OPS(prototype_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	u32 cpu;
	cpu = pick_idle_cpu012();
	if(cpu >= 0) {
		if(determine_tof(p)) {
		s64 laxity = (s64)p->dl.deadline - (s64)scx_bpf_now() - (s64)p->dl.runtime;
			if(SLACK_NS - laxity> 0) {
				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, /*SCX_SLICE_DEF*/, enq_flags);
				return cpu;
			}
		}
	}
	return prev_cpu;
	
/*
	if (cpu < 0) {
        bool direct = false;
        s32 dfl = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &direct);
        if (direct)
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
        return dfl;
    }
	enum bucket b = classify_deadline_task(p, now);

    if (b == BUCKET_NOW) {
#if defined(HAVE_LOCAL_ON_DIRECT_DISPATCH)
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | (u32)cpu, SLICE_NOW_NS ? SLICE_NOW_NS : SCX_SLICE_DFL, 0);
#else
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SLICE_NOW_NS ? SLICE_NOW_NS : SCX_SLICE_DFL, 0);
#endif
        return cpu;
    }
    u64 dsq = later_dsq_pick(p);
    scx_bpf_dsq_insert(p, dsq, SLICE_LATER_NS ? SLICE_LATER_NS : SCX_SLICE_DFL, 0);
    return cpu;
	*/
}

void BPF_STRUCT_OPS(prototype_enqueue, struct task_struct *p, u64 enq_flags)
{
	const u64  border = 1000000ULL;
	const u64  now_border = 1000000ULL;
	const u64  later_border = 1000000ULL;
	if(determine_tof(p)) {
		if(p->dl.runtime <= new_border) {
			if ((bpf_get_prandom_u32() & 1) == 0)
				scx_bpf_dsq_insert(p, FAST, /*SCX_SLICE_DEF*/, enq_flags);
			else
				scx_bpf_dsq_insert(p, ALWAYS, /*SCX_SLICE_DEF*/, enq_flags);
			return;
		}
		if ((bpf_get_prandom_u32() & 1) == 0)
			scx_bpf_dsq_insert_vtime(p, NORMAL, /*SCX_SLICE_DEF*/, enq_flags);
		else
			scx_bpf_dsq_insert_vtime(p, LATER, /*SCX_SLICE_DEF*/, enq_flags);
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

/*
void BPF_STRUCT_OPS(prototype_dispatch, s32 cpu, struct task_struct *prev)
{
    __u32 zero = 0, one = 1, two = 2;
    __u32 *now_rr  = bpf_map_lookup_elem(&scx_rr_state, &zero);
    __u32 *ltr_rr  = bpf_map_lookup_elem(&scx_rr_state, &one);
    __u32 *quota   = bpf_map_lookup_elem(&scx_rr_state, &two); 

    if (!now_rr || !ltr_rr || !quota) {
        return;
    }

    __u32 slots = scx_bpf_dispatch_nr_slots();
    if (!slots)
        return;

    if (*quota == 0)
        *quota = NOW_BURST;

    for (; slots > 0; ) {
        bool moved = false;

        while (*quota > 0 && slots > 0) {
            __u64 dsq_now = (*now_rr == 0) ? DSQ_FAST : DSQ_ALWAYS;
            *now_rr ^= 1; 

            if (scx_bpf_dsq_move_to_local(dsq_now)) {
                moved = true;
                (*quota)--;
                slots--;
            } else {
                __u64 dsq_alt = (*now_rr == 0) ? DSQ_FAST : DSQ_ALWAYS;
                *now_rr ^= 1;

                if (scx_bpf_dsq_move_to_local(dsq_alt)) {
                    moved = true;
                    (*quota)--;
                    slots--;
                } else {
                    *quota = 0;
                    break;
                }
            }
        }
        if (slots > 0) {
            __u32 ltr_try = LTR_BURST;

            while (ltr_try-- > 0 && slots > 0) {
                __u64 dsq_ltr = (*ltr_rr == 0) ? DSQ_NORMAL : DSQ_LATER;
                *ltr_rr ^= 1;
                if (scx_bpf_dsq_move_to_local(dsq_ltr)) {
                    moved = true;
                    slots--;
                } else {
                    __u64 dsq_alt = (*ltr_rr == 0) ? DSQ_NORMAL : DSQ_LATER;
                    *ltr_rr ^= 1;
                    if (scx_bpf_dsq_move_to_local(dsq_alt)) {
                        moved = true;
                        slots--;
                    }
                }
            }
        }
        if (!moved) {
            if (scx_bpf_dsq_move_to_local(SCX_DSQ_GLOBAL)) {
                slots--;
                continue;
            }
            break;
        }

        if (*quota == 0)
            *quota = NOW_BURST;
    }
}
*/
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
