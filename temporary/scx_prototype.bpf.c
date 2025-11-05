//SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <scx/common.bpf.h>
#include <bpf/bpf_core_read.h>

#ifndef SCHED_DEADLINE
#define SCHED_DEADLINE 6
#endif

char _license[] SEC("license") = "GPL";

const __s32 ALLOWED_CPUS[3] = {0, 1, 2};

#define FAST 0x1000ULL
#define NORMAL 0x2000ULL

#define SLACK_NS 500000ULL
#define DL_SMALL_NS 1000000ULL
#define CFS_UTIL_SMALL 128

#define CPU_NUM 4

int stage = 0;

enum { STG_COOL, STG_WARM, STG_HOT, STG_NR };

struct ratio {
	__u32 now, later;
};

struct credit_pair {
	__u32 now, later;
};


/*
struct ratio {
	u32 now, later;
};

struct credit_pair {
	u32 now, later;
};


*/

struct soft_deadline {
    __u64 abs_deadline_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct soft_deadline);
} soft_deadlines SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct credit_pair);
} credits SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} last_normal_dispatch SEC(".maps");

const volatile __u64 NORMAL_GUARD_NS = 5ULL * 1000 * 1000 * 1000;

const volatile struct ratio g_ratio[STG_NR] = {
    [STG_COOL] = {5, 3}, [STG_WARM] = {7, 3}, [STG_HOT] = {3, 1},
};

const volatile struct ratio g_ratio_nr = { 1, 0 };

struct stage_tunables {
    __u64 slack_ns;
    __u64 now_border_ns;
    __u64 dl_small_ns;
};

const volatile struct stage_tunables g_tune[STG_NR] = {
    [STG_COOL] = { 300000ULL, 1000000ULL, 1000000ULL },
    [STG_WARM] = { 250000ULL,  750000ULL, 1000000ULL },
    [STG_HOT]  = { 200000ULL,  500000ULL, 1000000ULL },
};

const volatile struct stage_tunables g_tune_nr = { 150000ULL, 250000ULL, 1000000ULL };

volatile __u32 g_rr_cpu;

const volatile __s32 rising_degC[4] = { 0, 67, 72, 77 };
const volatile __s32 falling_degC[4] = { 0, 64, 69, 74 };

const volatile __s32 g_filter_tz_id = -1;

volatile __u32 g_stage = STG_COOL;

UEI_DEFINE(uei);

static u64 vtime_now;

static __always_inline bool vtime_before(__u64 a, __u64 b)
{
    return (s64)(a - b) < 0;
}

static __always_inline __u64 get_slack_ns(void)
{
    __u32 st = g_stage;
    switch (st) {
    case STG_COOL:
	return g_tune[STG_COOL].slack_ns;
    case STG_WARM:
	return g_tune[STG_WARM].slack_ns;
    case STG_HOT:
	return g_tune[STG_HOT].slack_ns;
    default:
	return g_tune_nr.slack_ns;
    }
//    return (g_stage == STG_NR) ? g_tune_nr.slack_ns : g_tune[g_stage].slack_ns;
}
static __always_inline __u64 get_now_border_ns(void)
{
    __u32 st = g_stage;
    switch (st) {
    case STG_COOL:
	return g_tune[STG_COOL].now_border_ns;
    case STG_WARM:
	return g_tune[STG_WARM].now_border_ns;
    case STG_HOT:
	return g_tune[STG_HOT].now_border_ns;
    default:
	return g_tune_nr.now_border_ns;
    }
//    return (g_stage == STG_NR) ? g_tune_nr.now_border_ns : g_tune[g_stage].now_border_ns;
}
static __always_inline __u64 get_dl_small_ns(void)
{
    __u32 st = g_stage;
    switch (st) {
    case STG_COOL:
	return g_tune[STG_COOL].dl_small_ns;
    case STG_WARM:
	return g_tune[STG_WARM].dl_small_ns;
    case STG_HOT:
	return g_tune[STG_HOT].dl_small_ns;
    default:
	return g_tune_nr.dl_small_ns;
    }
//    return (g_stage == STG_NR) ? g_tune_nr.dl_small_ns : g_tune[g_stage].dl_small_ns;
}

static __always_inline struct ratio get_ratio_val(void)
{
    __u32 st = g_stage;
    struct ratio out;
    switch (st) {
    case STG_COOL:
        out.now = g_ratio[STG_COOL].now; out.later = g_ratio[STG_COOL].later; break;
    case STG_WARM:
        out.now = g_ratio[STG_WARM].now; out.later = g_ratio[STG_WARM].later; break;
    case STG_HOT:
        out.now = g_ratio[STG_HOT].now;  out.later = g_ratio[STG_HOT].later;  break;
    default:
        out.now = g_ratio_nr.now;        out.later = g_ratio_nr.later;        break;
    }
    return out;
}

static __always_inline __u32 next_stage_hysteresis(__u32 cur, int temp_mC, const volatile __s32 *rC, const volatile __s32 *dC)
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

static __always_inline __u32 dispatch_cap_for_stage(void)
{
    switch (g_stage) {
    case STG_COOL: return 16;
    case STG_WARM: return 8;
    case STG_HOT:  return 4;
    default:       return 2;
    }
}


static __always_inline bool determine_tof(const struct task_struct *p)
{
    if (p->policy != SCHED_DEADLINE)
        return false;
    if (bpf_core_field_exists(p->dl.dl_throttled)) {
        if (p->dl.dl_throttled)
            return false;
    }
    if (bpf_core_field_exists(p->dl.dl_non_contending)) {
        if (p->dl.dl_non_contending)
            return false;
    }
/*
    if (bpf_core_field_exists(p->dl.dl_boosted)) {
        if (p->dl.dl_boosted)
            return true;
    }
*/
    s64 runtime  = p->dl.runtime;
    s64 deadline = p->dl.deadline;
    if (runtime <= 0)
        return false;

    s64 laxity = deadline - (s64)bpf_ktime_get_ns() - runtime;
    return laxity > 0;
/*
    if ((p->policy != SCHED_DEADLINE) || p->dl_throttled == 1 || p->dl_non_contending == 1)
		return false;
    if ((s64)p->dl.runtime <= 0)
        return false;
	if (p->dl.dl_boosted)
        return true;
	s64 laxity = (s64)p->dl.deadline - (s64)bpf_ktime_get_ns() - (s64)p->dl.runtime;
    return laxity > 0;
*/
}

static __always_inline bool cpu_online(s32 cpu)
{
    const struct cpumask *online = scx_bpf_get_online_cpumask();
    bool ok = online && cpu >= 0 && bpf_cpumask_test_cpu(cpu, online);
    if (online)
	scx_bpf_put_cpumask(online);
    return ok;
}

static __always_inline s32 pick_idle_cpu012(void)
{
    const struct cpumask *idle = scx_bpf_get_idle_cpumask();
    if (!idle)
		return -1;
    #pragma clang loop unroll(full)
    for (int i = 0; i < 3; i++) {
        s32 cpu = ALLOWED_CPUS[i];
        if (bpf_cpumask_test_cpu(cpu, idle)) {
            scx_bpf_put_idle_cpumask(idle);
            return cpu;
	}
    }
    scx_bpf_put_idle_cpumask(idle);
    return -1;
}


static __always_inline bool determine_sz(const struct task_struct *p)
{
    if (p->policy == SCHED_DEADLINE)
        return (u64)p->dl.runtime <= get_dl_small_ns();
    return p->se.avg.util_avg <= CFS_UTIL_SMALL;
}

static __always_inline s32 pick_target_cpu(void)
{
    const struct cpumask *idle = scx_bpf_get_idle_cpumask();
    if (idle) {
        for (int i = 0; i < 4; i++) {
            s32 cand = (g_rr_cpu + i) & 3;
            if (bpf_cpumask_test_cpu(cand, idle)) {
                scx_bpf_put_idle_cpumask(idle);
                return cand;
	    }
        }
        scx_bpf_put_idle_cpumask(idle);
    }
    s32 best = -1; __u64 best_depth = ~0ULL;
    for (int cpu = 0; cpu < 4; cpu++) {
		s32 depth_raw = scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu);
		__u64 depth = depth_raw < 0 ? 0 : (__u64)depth_raw;
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

    struct bpf_iter_scx_dsq it = {};
    struct task_struct *p;
    bool moved = false;

    int ret = bpf_iter_scx_dsq_new(&it, src_dsq, 0);
    if (ret)
        goto out_destroy;
//        return false;

#pragma clang loop unroll(disable)
    while ((p = bpf_iter_scx_dsq_next(&it))) {
        if (__COMPAT_scx_bpf_dsq_move(&it, p, SCX_DSQ_LOCAL_ON | target_cpu, 0)) {
            moved = true;
            break;
        }
    }
out_destroy:
    bpf_iter_scx_dsq_destroy(&it);
    return moved;
/*
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
*/
}

static __always_inline s64 task_slack_ns(const struct task_struct *p)
{
    __u64 now = bpf_ktime_get_ns();

    if (p->policy == SCHED_DEADLINE) {
        if (bpf_core_field_exists(p->dl.dl_throttled) &&
            p->dl.dl_throttled)
            return (s64)1e15;
        if (bpf_core_field_exists(p->dl.dl_non_contending) &&
            p->dl.dl_non_contending)
            return (s64)1e15;

        s64 runtime  = p->dl.runtime;
        s64 deadline = p->dl.deadline;
        if (runtime <= 0)
            return (s64)1e15;

        return deadline - (s64)now - runtime;
    }

    __u32 tgid = BPF_CORE_READ(p, tgid);
    struct soft_deadline *sd = bpf_map_lookup_elem(&soft_deadlines, &tgid);
    if (sd) {
        return (s64)sd->abs_deadline_ns - (s64)now;
    }

    return (s64)1e15;
}

static __always_inline bool task_is_urgent(const struct task_struct *p)
{
    s64 slack = task_slack_ns(p);
    __u64 border = get_now_border_ns();

    if (slack <= 0)
        return true;
    if (slack < (s64)border)
        return true;

    return false;
}



static __always_inline bool dispatch_one_weighted(bool force_normal)
{
/*
	u32 k = 0;
    struct credit_pair *c = bpf_map_lookup_elem(&credits, &k);

    if (!c)
	return false;
//    const struct ratio r = (g_stage == STG_NR) ? g_ratio_nr : g_ratio[g_stage];
    const struct ratio r = get_ratio_val();
    if (c->now == 0 && c->later == 0) {
		c->now = r.now;
		c->later = r.later;
	}

    bool try_now = (c->now >= c->later);
    #pragma clang loop unroll(full)
    for (int turn = 0; turn < 2; turn++) {
        __u64 dsq = try_now ? FAST : NORMAL;
//        s32 target = pick_target_cpu();
        if (scx_bpf_dsq_move_to_local(dsq)) {
            if (try_now)
		c->now--;
	    else
	        c->later--;
            g_rr_cpu++;
            return true;
        }
        try_now = !try_now;
    }
    return false;
*/
    u32 k = 0;
    struct credit_pair *c = bpf_map_lookup_elem(&credits, &k);
    if (!c)
        return false;

    const struct ratio r = get_ratio_val();
    if (c->now == 0 && c->later == 0) {
        c->now   = r.now;
        c->later = r.later;
    }
/*
    __u64 dsq = (c->now >= c->later) ? FAST : NORMAL;

    bool moved = scx_bpf_dsq_move_to_local(dsq);
    if (!moved)
        return false;

    if (dsq == FAST) c->now--; else c->later--;
    return true;
*/

    __u64 first = (c->now >= c->later) ? FAST : NORMAL;
    __u64 second = (first == FAST) ? NORMAL : FAST;

    s32 this_cpu = bpf_get_smp_processor_id();

    if (force_normal) {
        if (move_one(NORMAL, this_cpu)) {
            if (c->later > 0)
                c->later--;
            return true;
        }
    }

/*
//    if (scx_bpf_dsq_move_to_local(first)) {
    if (move_one(first, this_cpu)) {
        if (first == FAST) c->now--; else c->later--;
        return true;
    }

//    if (scx_bpf_dsq_move_to_local(second)) {
    if (move_one(second, this_cpu)) {
        if (second == FAST) c->now--; else c->later--;
        return true;
    }
*/
    if ((first == FAST  && !c->now) || (first == NORMAL && !c->later) || !scx_bpf_dsq_nr_queued(first))
        first = second;

    if ((first == FAST && !c->now) || (first == NORMAL && !c->later))
        return false;

    if (move_one(first, this_cpu)) {
        if (first == FAST) c->now--; else c->later--;
        return true;
    }

    return false;

}

s32 BPF_STRUCT_OPS(prototype_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	u32 cpu = pick_idle_cpu012();
	if (cpu < 0)
	    return prev_cpu;
    s64 slack = task_slack_ns(p);
    if (slack <= 0 || slack <= (s64)get_slack_ns()) {
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_DFL, 0);
        scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
        return cpu;
    }
/*
	if(cpu >= 0 && determine_tof(p)) {
	    s64 laxity = (s64)p->dl.deadline - (s64)bpf_ktime_get_ns()- (s64)p->dl.runtime;
	    if((s64)get_slack_ns() - laxity> 0) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_DFL, 0);
                scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
		return cpu;
	    }

	}
*/
	return prev_cpu;
}

//void BPF_STRUCT_OPS(prototype_enqueue, struct task_struct *p, u64 enq_flags)
s32 BPF_STRUCT_OPS(prototype_enqueue, struct task_struct *p, u64 enq_flags)
{
/*

    if(determine_tof(p) && (p->dl.runtime <= get_now_border_ns())) {
	scx_bpf_dsq_insert(p, FAST, SCX_SLICE_DFL, enq_flags);
	return 0;
    }
*/
    if (task_is_urgent(p)) {
        scx_bpf_dsq_insert(p, FAST, SCX_SLICE_DFL, enq_flags);
        return 0;
    }

    __u64 v = p->scx.dsq_vtime;

    if (vtime_before(v, vtime_now - SCX_SLICE_DFL))
        v = vtime_now - SCX_SLICE_DFL;

    scx_bpf_dsq_insert_vtime(p, NORMAL, SCX_SLICE_DFL, v, enq_flags);

    return 0;
}

//void BPF_STRUCT_OPS(prototype_dequeue, struct task_struct *p, u64 deq_flags)
s32 BPF_STRUCT_OPS(prototype_dequeue, struct task_struct *p, u64 deq_flags)
{
    return 0;
}

//void BPF_STRUCT_OPS(prototype_dispatch, s32 cpu, struct task_struct *prev)
s32 BPF_STRUCT_OPS(prototype_dispatch, s32 cpu, struct task_struct *prev)
{
/*
    __u32 slots = scx_bpf_dispatch_nr_slots();
    #pragma clang loop unroll(disable)
    for (__u32 i = 0; i < 20; i++) {
	if (i >= slots)
	    break;
        if (!dispatch_one_weighted())
            break;
    }
    //return 0;
*/
    __u32 slots = scx_bpf_dispatch_nr_slots();
    if (slots == 0)
        return 0;

    __u32 cap = dispatch_cap_for_stage();
    __u32 budget = slots < cap ? slots : cap;

    bool force_norm = false;

    {
        u32 k = 0;
        __u64 *last = bpf_map_lookup_elem(&last_normal_dispatch, &k);
        if (last) {
            __u64 now = bpf_ktime_get_ns();

            s32 dq = scx_bpf_dsq_nr_queued(NORMAL);
            __u64 depth = dq < 0 ? 0 : (__u64)dq;

            if (depth > 0 && now - *last >= NORMAL_GUARD_NS) {
                force_norm = true;
                *last = now;
            }
        }
    }

    if (budget > 0) {
        if (!dispatch_one_weighted(force_norm))
            return 0;
        budget--;
    }

    #pragma clang loop unroll(disable)
    for (__u32 i = 0; i < budget; i++) {
        if (!dispatch_one_weighted(false))
            break;
    }
    return 0;
}



SEC("tracepoint/thermal/thermal_temperature")
int tp_thermal(struct trace_event_raw_thermal_temperature *ctx)
{
    if (g_filter_tz_id >= 0 && ctx->id != g_filter_tz_id)
        return 0;

    const int temp_mC = ctx->temp;

    __u32 cur = g_stage;
    __u32 nxt = next_stage_hysteresis(cur, temp_mC, rising_degC, falling_degC);
    if (nxt != cur) {
    	g_stage = nxt;
	u32 k = 0;
    	struct credit_pair *c = bpf_map_lookup_elem(&credits, &k);
    	if (c) {
            c->now = 0;
            c->later = 0;
	}
     }

    return 0;
}


s32 BPF_STRUCT_OPS_SLEEPABLE(prototype_init)
{
    scx_bpf_create_dsq(FAST, -1);
    scx_bpf_create_dsq(NORMAL, -1);
    //scx_bpf_switch_all();
    //scx_bpf_create_dsq(GOAWAY, -1);
    //scx_bpf_create_dsq(EMERGENCY, -1);
    //scx_bpf_create_dsq(ALWAYS, -1);
    //scx_bpf_create_dsq(LATER, -1);
	return 0;
}
void BPF_STRUCT_OPS(prototype_exit, struct scx_exit_info *ei)
{
    UEI_RECORD(uei, ei);
    scx_bpf_destroy_dsq(FAST);
    scx_bpf_destroy_dsq(NORMAL);
    //scx_bpf_destroy_dsq(GOAWAY);
}

s32 BPF_STRUCT_OPS(prototype_init_task, struct task_struct *p, struct scx_init_task_args *args) 
{
	return 0;
}

void BPF_STRUCT_OPS(prototype_running, struct task_struct *p)
{
    if (time_before(vtime_now, p->scx.dsq_vtime))
        vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(prototype_stopping, struct task_struct *p, bool runnable)
{
    p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

void BPF_STRUCT_OPS(prototype_enable, struct task_struct *p)
{
    p->scx.dsq_vtime = vtime_now;
}


//SEC(".struct_ops") struct sched_ext_ops prototype_ops = {
SCX_OPS_DEFINE(prototype_ops,
.select_cpu	= (void *)prototype_select_cpu,
.enqueue 	= (void *)prototype_enqueue,
.dispatch 	= (void *)prototype_dispatch,
.dequeue 	= (void *)prototype_dequeue,
.init 		= (void *)prototype_init,
.init_task 	= (void *)prototype_init_task,
.exit 		= (void *)prototype_exit,
.running   	= (void *)prototype_running,
.stopping  	= (void *)prototype_stopping,
.enable    	= (void *)prototype_enable,
.flags		= SCX_OPS_SWITCH_PARTIAL,
.name 		= "scx_prototype");
