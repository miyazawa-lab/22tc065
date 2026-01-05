pi@raspberrypi:~ $ cat scx/scheds/c/scx_prototype.bpf.c
// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <scx/common.bpf.h>

#ifndef SCHED_NORMAL
#define SCHED_NORMAL 0
#endif

#ifndef SCHED_FIFO
#define SCHED_FIFO   1
#endif

#ifndef SCHED_RR
#define SCHED_RR     2
#endif

#ifndef SCHED_BATCH
#define SCHED_BATCH  3
#endif

#ifndef SCHED_IDLE
#define SCHED_IDLE   5
#endif

#ifndef SCHED_DEADLINE
#define SCHED_DEADLINE 6
#endif

char _license[] SEC("license") = "GPL";

const __s32 ALLOWED_CPUS[3] = { 0, 1, 2 };

#define FAST   0x1000ULL   /* ユーザー空間の「今やる」キュー */
#define NORMAL 0x2000ULL   /* ユーザー空間の「後回し」キュー */
//#define KERNEL 0x3000ULL   /* カーネル専用キュー */
#define KERNEL_BASE 0x3000ULL   /* per-CPU kernel DSQ base */
#define KERNEL_DSQ(cpu) (KERNEL_BASE | (__u64)((cpu) & 0xff))


#define SLACK_NS      500000ULL
#define DL_SMALL_NS   1000000ULL
#define CFS_UTIL_SMALL 128

#define CPU_NUM 4


#define USER_DISPATCH_MAX   16
#define KERNEL_DRAIN_MAX    64

int stage = 0;

enum { STG_COOL, STG_WARM, STG_HOT, STG_NR };

/* FAST / NORMAL の参照比率用 */
struct ratio {
        __u32 now, later;
};
/*
struct credit_pair {
        __u32 now, later;
};
*/

struct wrr_state {
        __u32 acc;
};

struct soft_deadline {
        __u64 abs_deadline_ns;
};

/* DSQ の深さをユーザー空間に見せる用 */
struct dsq_depth {
        s32 kernel_q;
        s32 fast_q;
        s32 normal_q;
};

/* DSQ 参照回数の統計 */
struct dsq_stats {
        __u64 fast;     /* FAST に入れた回数 */
        __u64 normal;   /* NORMAL に入れた回数 */
        __u64 local;    /* ローカル DSQ へ直接入れた回数 */
        __u64 kernel;   /* KERNEL DSQ に入れた回数 */
};

/* 手動分類用フラグ（ユーザー空間から設定） */
#define CLASS_FAST  (1U << 0)  /* 明示的に「今やる」 */
#define CLASS_BG    (1U << 1)  /* 明示的に「後回し」 */

struct task_class {
        __u32 flags;
};

/* 手動分類マップ（tgid -> flags）、ユーザー空間から操作する用 */
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 1024);
        __type(key, __u32);              /* tgid */
        __type(value, struct task_class);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} task_class_map SEC(".maps");

/* DSQ 参照統計 */
struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, struct dsq_stats);
} dsq_stats SEC(".maps");

/* soft_deadline (ユーザー空間から set_soft_deadline で更新) */
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 1024);
        __type(key, __u32);              /* tgid */
        __type(value, struct soft_deadline);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} soft_deadlines SEC(".maps");

/* FAST/NORMAL 比率制御用クレジット（CPU毎） */
struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
//      __type(value, struct credit_pair);
        __type(value, struct wrr_state);
} credits SEC(".maps");

/* 「しばらく NORMAL を吐いていない」判定用タイムスタンプ */
struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, __u64);
} last_normal_dispatch SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, __u64);
} last_fast_dispatch SEC(".maps");

/* DSQ 深さ */
struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, struct dsq_depth);
} dsq_depth_map SEC(".maps");

const volatile __u64 NORMAL_GUARD_NS = 200ULL * 1000 * 1000;

const volatile __u64 FAST_GUARD_NS   = 2ULL * 1000 * 1000;

/* 温度ステージごとの FAST/NORMAL 比率 */
/*
const volatile struct ratio g_ratio[STG_NR] = {
        [STG_COOL] = { 4,  6 },
        [STG_WARM] = { 4,  8 },
        [STG_HOT]  = { 4, 10 },
};
*/

/*
const volatile struct ratio g_ratio[STG_NR] = {
        [STG_COOL] = { 10,  22 },
        [STG_WARM] = { 4,  12 },
        [STG_HOT]  = { 2,  6 },
};
*/

const volatile struct ratio g_ratio[STG_NR] = {
        [STG_COOL] = { 13,  19 },
        [STG_WARM] = { 6,  10 },
        [STG_HOT]  = { 5,  3 },
};


const volatile struct ratio g_ratio_nr = { 1, 0 };

/* 温度ステージごとのしきい値群 */
struct stage_tunables {
        __u64 slack_ns;
        __u64 now_border_ns;
        __u64 dl_small_ns;
};

const volatile struct stage_tunables g_tune[STG_NR] = {
        [STG_COOL] = { 300000ULL, 500000ULL, 1000000ULL },
        [STG_WARM] = { 250000ULL, 400000ULL, 1000000ULL },
        [STG_HOT]  = { 200000ULL, 300000ULL, 1000000ULL },
};

const volatile struct stage_tunables g_tune_nr = {
        .slack_ns     = 150000ULL,
        .now_border_ns = 250000ULL,
        .dl_small_ns  = 1000000ULL,
};

volatile __u32 g_rr_cpu;


const volatile __s32 rising_degC[4]  = { 0, 67, 72, 77 };
const volatile __s32 falling_degC[4] = { 0, 64, 69, 74 };


/*
const volatile __s32 rising_degC[4]  = { 0, 64, 69, 75 };
const volatile __s32 falling_degC[4] = { 0, 60, 66, 72 };
*/

const volatile __s32 g_filter_tz_id = -1;

/* 温度ベースのステージ */
volatile __u32 g_stage = STG_COOL;

/* ユーザー空間で調整したい「負荷ステージ」 */
#define NUM_LOAD_STAGES 10

enum {
        LOAD_STG_0 = 0,
        LOAD_STG_1,
        LOAD_STG_2,
        LOAD_STG_3,
        LOAD_STG_4,
        LOAD_STG_5,
        LOAD_STG_6,
        LOAD_STG_7,
        LOAD_STG_8,
        LOAD_STG_9,
        LOAD_STG_OVERLOAD,
        LOAD_STG_NR = LOAD_STG_OVERLOAD + 1,
};

volatile __u32 g_load_stage = LOAD_STG_0;

/* 負荷ステージごとの slack しきい値（小さいほど厳しい） */
const volatile __u64 g_load_stage_border_ns[LOAD_STG_NR] = {
        3000000ULL,  /* 0: 3.0ms */
        2500000ULL,  /* 1: 2.5ms */
        2000000ULL,  /* 2: 2.0ms */
        1500000ULL,  /* 3: 1.5ms */
        1200000ULL,  /* 4: 1.2ms */
        1000000ULL,  /* 5: 1.0ms */
         800000ULL,  /* 6: 0.8ms */
         600000ULL,  /* 7: 0.6ms */
         500000ULL,  /* 8: 0.5ms */
         400000ULL,  /* 9: 0.4ms */
         300000ULL,  /* overload: 0.3ms */
};

/* キュー深さを見て負荷ステージを上下させるためのヒステリシスしきい値 */
const volatile __s32 rising_q_depth_thresholds[LOAD_STG_NR] = {
        0,
        5,
        10,
        15,
        20,
        25,
        30,
        35,
        40,
        45,
        50,
};

const volatile __s32 falling_q_depth_thresholds[LOAD_STG_NR] = {
        0,
        3,
        8,
        13,
        18,
        23,
        28,
        33,
        38,
        43,
        48,
};

UEI_DEFINE(uei);

static u64 vtime_now;

static __always_inline bool vtime_before(__u64 a, __u64 b)
{
        return (s64)(a - b) < 0;
}

/* DSQ stats をインクリメントするヘルパ */
static __always_inline void dsq_stats_inc(__u32 idx)
{
        __u32 k = 0;
        struct dsq_stats *s = bpf_map_lookup_elem(&dsq_stats, &k);
        if (!s)
                return;

        switch (idx) {
        case 0: /* FAST */
                s->fast++;
                break;
        case 1: /* NORMAL */
                s->normal++;
                break;
        case 2: /* LOCAL */
                s->local++;
                break;
        case 3: /* KERNEL */
                s->kernel++;
                break;
        default:
                break;
        }
}

/* DSQ の深さを map に書き出す（KERNEL/FAST/NORMAL） */
static __always_inline void update_dsq_depth(void)
{
        __u32 k = 0;
        struct dsq_depth *d = bpf_map_lookup_elem(&dsq_depth_map, &k);
        if (!d)
                return;

//      d->kernel_q = scx_bpf_dsq_nr_queued(KERNEL);

    s32 k0 = scx_bpf_dsq_nr_queued(KERNEL_DSQ(0));
    s32 k1 = scx_bpf_dsq_nr_queued(KERNEL_DSQ(1));
    s32 k2 = scx_bpf_dsq_nr_queued(KERNEL_DSQ(2));
    s32 k3 = scx_bpf_dsq_nr_queued(KERNEL_DSQ(3));
    d->kernel_q = (k0 > 0 ? k0 : 0) + (k1 > 0 ? k1 : 0) + (k2 > 0 ? k2 : 0) + (k3 > 0 ? k3 : 0);

        d->fast_q   = scx_bpf_dsq_nr_queued(FAST);
        d->normal_q = scx_bpf_dsq_nr_queued(NORMAL);
}

/* task_class_map から手動分類フラグを読む */
static __always_inline __u32 get_task_class_flags(const struct task_struct *p)
{
        __u32 tgid = BPF_CORE_READ(p, tgid);
        struct task_class *c = bpf_map_lookup_elem(&task_class_map, &tgid);
        if (!c)
                return 0;
        return c->flags;
}

/* カーネル kthread 判定：mm == NULL */
static __always_inline bool is_kernel_kthread(const struct task_struct *p)
{
        struct mm_struct *mm = BPF_CORE_READ(p, mm);
        return mm == NULL;
}

/* 負荷ステージ更新（FAST+NORMAL の合計深さを見て上下） */
static __always_inline __u32 next_load_stage_hysteresis(__u32 cur_stage,
                                                        s32 current_q_depth)
{
        if (cur_stage >= LOAD_STG_OVERLOAD) {
                if (current_q_depth < falling_q_depth_thresholds[LOAD_STG_OVERLOAD])
                        return LOAD_STG_9;
                return LOAD_STG_OVERLOAD;
        }

        if (cur_stage >= LOAD_STG_NR)
                cur_stage = LOAD_STG_0;

        if (cur_stage + 1 < LOAD_STG_NR &&
            current_q_depth >= rising_q_depth_thresholds[cur_stage + 1])
                return cur_stage + 1;

        if (cur_stage > LOAD_STG_0 &&
            current_q_depth < falling_q_depth_thresholds[cur_stage])
                return cur_stage - 1;

        return cur_stage;
}

/* 温度ステージから slack_ns を取得 */
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
}

/* 温度と負荷を合わせた「今やる/後回し」境界 */
static __always_inline __u64 get_now_border_ns(void)
{
        __u64 temp_based_border_ns;
        __u32 st = g_stage;

        switch (st) {
        case STG_COOL:
                temp_based_border_ns = g_tune[STG_COOL].now_border_ns;
                break;
        case STG_WARM:
                temp_based_border_ns = g_tune[STG_WARM].now_border_ns;
                break;
        case STG_HOT:
                temp_based_border_ns = g_tune[STG_HOT].now_border_ns;
                break;
        default:
                temp_based_border_ns = g_tune_nr.now_border_ns;
                break;
        }

        __u64 load_based_border_ns;
        __u32 ls = g_load_stage;

        if (ls < LOAD_STG_NR)
                load_based_border_ns = g_load_stage_border_ns[ls];
        else
                load_based_border_ns = g_load_stage_border_ns[LOAD_STG_OVERLOAD];

        return (temp_based_border_ns < load_based_border_ns) ?
                temp_based_border_ns : load_based_border_ns;
}

/* デッドラインの「小さい」のしきい値 */
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
}

/* 温度ステージに応じた FAST/NORMAL 比率 */
static __always_inline struct ratio get_ratio_val(void)
{
        __u32 st = g_stage;
        struct ratio out;

        switch (st) {
        case STG_COOL:
                out.now   = g_ratio[STG_COOL].now;
                out.later = g_ratio[STG_COOL].later;
                break;
        case STG_WARM:
                out.now   = g_ratio[STG_WARM].now;
                out.later = g_ratio[STG_WARM].later;
                break;
        case STG_HOT:
                out.now   = g_ratio[STG_HOT].now;
                out.later = g_ratio[STG_HOT].later;
                break;
        default:
                out.now   = g_ratio_nr.now;
                out.later = g_ratio_nr.later;
                break;
        }
        return out;
}

/* 温度ヒステリシス */
static __always_inline __u32 next_stage_hysteresis(__u32 cur, int temp_mC,
                                                   const volatile __s32 *rC,
                                                   const volatile __s32 *dC)
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
                if (temp_mC < d_cool_mC)
                        return STG_COOL;
                return STG_WARM;
        case STG_HOT:
                if (temp_mC >= r_nr_mC)
                        return STG_NR;
                if (temp_mC < d_warm_mC)
                        return STG_WARM;
                return STG_HOT;
        case STG_NR:
        default:
                return (temp_mC < d_hot_mC) ? STG_HOT : STG_NR;
        }
}

/* ステージごとの dispatch 上限 */
static __always_inline __u32 dispatch_cap_for_stage(void)
{
        switch (g_stage) {
        case STG_COOL:
                return 32;
        case STG_WARM:
                return 16;
        case STG_HOT:
                return 8;
        default:
                return 4;
        }
}

/* CPU オンラインチェック */
static __always_inline bool cpu_online(s32 cpu)
{
        const struct cpumask *online = scx_bpf_get_online_cpumask();
        bool ok = online && cpu >= 0 && bpf_cpumask_test_cpu(cpu, online);

        if (online)
                scx_bpf_put_cpumask(online);
        return ok;
}

/* ALLOWED_CPUS から idle を一つ選ぶ */
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

/* CFS util / DL runtime が「小さいか」 */
static __always_inline bool determine_sz(const struct task_struct *p)
{
        if (p->policy == SCHED_DEADLINE)
                return (u64)p->dl.runtime <= get_dl_small_ns();
        return p->se.avg.util_avg <= CFS_UTIL_SMALL;
}


static __always_inline bool kernel_task_must_run_on_cpu(const struct task_struct *p, s32 cpu)
{
/*
        if (!is_kernel_kthread(p))
                return false;

        int n_allowed = BPF_CORE_READ(p, nr_cpus_allowed);
        const struct cpumask *mask = BPF_CORE_READ(p, cpus_ptr);
        if (n_allowed == 1 && mask && bpf_cpumask_test_cpu(cpu, mask))
                return true;
        return false;
*/

        if (!is_kernel_kthread(p))
                return false;

        /* 許可CPUが1つだけのタスクに限定して確認 */
        int n_allowed = BPF_CORE_READ(p, nr_cpus_allowed);
        if (n_allowed != 1)
                return false;

        /* 重要: cpumask kfunc には p->cpus_ptr を「直接」渡す */
        /* 例: if (bpf_cpumask_test_cpu(0, task->cpus_ptr)) ... というのが公 式のやり方 */
        u32 only = bpf_cpumask_first(p->cpus_ptr);
        return only == (u32)cpu;

}

/* ローカル DSQ の深さが最も浅い CPU を選ぶ（バックアップ用） */
static __always_inline s32 pick_target_cpu(void)
{
        const struct cpumask *idle = scx_bpf_get_idle_cpumask();

        if (idle) {
                for (int i = 0; i < CPU_NUM; i++) {
                        s32 cand = (g_rr_cpu + i) & 3;

                        if (bpf_cpumask_test_cpu(cand, idle)) {
                                scx_bpf_put_idle_cpumask(idle);
                                return cand;
                        }
                }
                scx_bpf_put_idle_cpumask(idle);
        }

        s32 best = -1;
        __u64 best_depth = ~0ULL;

        for (int cpu = 0; cpu < CPU_NUM; cpu++) {
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

/* 任意 DSQ から 1 task を local or remote DSQ へ移す */

static __always_inline bool move_one(__u64 src_dsq)
{
        return scx_bpf_dsq_move_to_local(src_dsq);
 }

/*
static __always_inline bool move_one(__u64 src_dsq, s32 target_cpu)
{
        s32 this_cpu = bpf_get_smp_processor_id();

        if (target_cpu == this_cpu)
                return scx_bpf_dsq_move_to_local(src_dsq);

        struct bpf_iter_scx_dsq it = {};
        struct task_struct *p;
        bool moved = false;
        int ret;

        ret = bpf_iter_scx_dsq_new(&it, src_dsq, 0);
        if (ret)
                goto out_destroy;

#pragma clang loop unroll(disable)
        while ((p = bpf_iter_scx_dsq_next(&it))) {
                if (__COMPAT_scx_bpf_dsq_move(&it, p,
                                              SCX_DSQ_LOCAL_ON | target_cpu, 0)) {
                        moved = true;
                        break;
                }
        }
out_destroy:
        bpf_iter_scx_dsq_destroy(&it);
        return moved;
}
*/
/* タスクの「余裕時間」slack(ns) を計算（無い場合は超巨大値 = 非緊急扱い） */
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

        if (sd)
                return (s64)sd->abs_deadline_ns - (s64)now;

        return (s64)1e15;
}

/*
 * ユーザー空間タスクの「今やるかどうか」を判定
 *  - 手動分類 (CLASS_FAST/CLASS_BG)
 *  - slack vs get_now_border_ns()
 *  - policy & util/runtime
 */
static __always_inline bool task_is_urgent_user(const struct task_struct *p)
{
        __u32 class_flags = get_task_class_flags(p);

        if (class_flags & CLASS_FAST)
                return true;
        if (class_flags & CLASS_BG)
                return false;

        s64 slack = task_slack_ns(p);
        __u64 border = get_now_border_ns();

        if (slack <= 0)
                return true;

        if (slack > (s64)(border * 2))
                return false;

        if (p->policy == SCHED_FIFO || p->policy == SCHED_RR) {
                if (g_stage == STG_COOL)
                        return true;
                return slack < (s64)border;
        }

        if (p->policy == SCHED_NORMAL ||
            p->policy == SCHED_BATCH ||
            p->policy == SCHED_IDLE) {
                if (slack < (s64)border && determine_sz(p))
                        return true;
                return false;
        }

        return false;
}

/*
 * FAST/NORMAL の重み付き dispatch
 *  ※KERNEL はここには混ぜない。KERNEL は dispatch 冒頭で必ず処理する。
 */
enum { PICK_NONE = 0, PICK_FAST = 1, PICK_NORMAL = 2 };

/*
 * バーストしない WRR (accumulator)：
 *   acc += now;
 *   if acc >= now+later => FAST（acc -= total）
 *   else               => NORMAL
 *
 * ※ 4:10 でも NORMAL が 10 連発しにくくなる（FAST の最悪待ちを縮める）
 */
static __always_inline bool dispatch_one_wrr(bool force_normal, __u32 *picked)
{
        __u32 k = 0;
        struct wrr_state *st = bpf_map_lookup_elem(&credits, &k);
//        s32 cpu = bpf_get_smp_processor_id();
        struct ratio r = get_ratio_val();
        s32 fast_q = scx_bpf_dsq_nr_queued(FAST);
        s32 normal_q = scx_bpf_dsq_nr_queued(NORMAL);
        bool has_fast = fast_q > 0;
        bool has_normal = normal_q > 0;

        if (picked)
                *picked = PICK_NONE;
        if (!st)
                return false;

        if (!has_fast && !has_normal)
                return false;
        if (!has_fast && has_normal) {
                if (move_one(NORMAL)) {
//                if (move_one(NORMAL, cpu)) {
                        if (picked) *picked = PICK_NORMAL;
                        return true;
                }
                return false;
        }
        if (has_fast && !has_normal) {
            if (move_one(FAST)) {
//            if (move_one(FAST, cpu)) {
                        if (picked) *picked = PICK_FAST;
                        return true;
                }
                return false;
        }

        /* ここから FAST/NORMAL 両方あり */
        if (force_normal) {
                if (move_one(NORMAL)) {
//                if (move_one(NORMAL, cpu)) {
                        if (picked) *picked = PICK_NORMAL;
                        return true;
                }
                /* 失敗したら通常ロジックへ */
        }

        __u32 total = r.now + r.later;
        if (!total) {
                if (move_one(FAST)) {
//                if (move_one(FAST, cpu)) {
                        if (picked) *picked = PICK_FAST;
                        return true;
                }
                if (move_one(NORMAL)) {
//                if (move_one(NORMAL, cpu)) {
                        if (picked) *picked = PICK_NORMAL;
                        return true;
                }
                return false;
        }

        st->acc += r.now;
        bool pick_fast = st->acc >= total;
        if (pick_fast)
                st->acc -= total;

        if (pick_fast) {
                if (move_one(FAST)) {
//                if (move_one(FAST, cpu)) {
                        if (picked) *picked = PICK_FAST;
                        return true;
                }
                if (move_one(NORMAL)) {
//                if (move_one(NORMAL, cpu)) {
                        if (picked) *picked = PICK_NORMAL;
                        return true;
                }
                 return false;
       } else {
                if (move_one(NORMAL)) {
//                if (move_one(NORMAL, cpu)) {
                        if (picked) *picked = PICK_NORMAL;
                        return true;
                }
                if (move_one(FAST)) {
//                if (move_one(FAST, cpu)) {
                        if (picked) *picked = PICK_FAST;
                        return true;
                }
                return false;
        }
}
/*
static __always_inline bool dispatch_one_weighted(bool force_normal)
{
        __u32 k = 0;
        struct credit_pair *c = bpf_map_lookup_elem(&credits, &k);
        s32 this_cpu = bpf_get_smp_processor_id();
        const struct ratio r = get_ratio_val();
        s32 fast_q, normal_q;
        bool has_fast, has_normal;
        __u64 first, second;

        if (!c)
                return false;

        fast_q   = scx_bpf_dsq_nr_queued(FAST);
        normal_q = scx_bpf_dsq_nr_queued(NORMAL);

        has_fast   = fast_q   > 0;
        has_normal = normal_q > 0;
        if (!has_fast && !has_normal)
                return false;

        if (!has_fast && has_normal)
                return move_one(NORMAL, this_cpu);

        if (has_fast && !has_normal)
                return move_one(FAST, this_cpu);

        if (c->now == 0 && c->later == 0) {
                c->now   = r.now;
                c->later = r.later;
        }
        if (has_normal && c->later == 0) {
                c->now   = r.now;
                c->later = r.later;
        }

        if (force_normal) {
                if (move_one(NORMAL, this_cpu)) {
                        if (c->later > 0)
                                c->later--;
                        return true;
                }
        }

        first  = (c->now >= c->later) ? FAST : NORMAL;
        second = (first == FAST) ? NORMAL : FAST;

        if ((first == FAST  && (!c->now || !has_fast)) ||
            (first == NORMAL && (!c->later || !has_normal)))
                first = second;

        if ((first == FAST  && (!c->now || !has_fast)) ||
            (first == NORMAL && (!c->later || !has_normal)))
                return false;

        if (move_one(first, this_cpu)) {
                if (first == FAST && c->now > 0)
                        c->now--;
                else if (first == NORMAL && c->later > 0)
                        c->later--;
                return true;
        }

        return false;
}
*/
/*
static __always_inline bool dispatch_one_weighted(bool force_normal)
{
        __u32 k = 0;
        struct credit_pair *c = bpf_map_lookup_elem(&credits, &k);
        s32 this_cpu = bpf_get_smp_processor_id();
        const struct ratio r = get_ratio_val();
        __u64 first, second;

        if (!c)
                return false;

        if (c->now == 0 && c->later == 0) {
                c->now   = r.now;
                c->later = r.later;
        }

        first  = (c->now >= c->later) ? FAST : NORMAL;
        second = (first == FAST) ? NORMAL : FAST;

        if (force_normal) {
                if (move_one(NORMAL, this_cpu)) {
                        if (c->later > 0)
                                c->later--;
                        return true;
                }
        }

        if ((first == FAST  && !c->now) ||
            (first == NORMAL && !c->later) ||
            !scx_bpf_dsq_nr_queued(first))
                first = second;

        if ((first == FAST  && !c->now) ||
            (first == NORMAL && !c->later))
                return false;

        if (move_one(first, this_cpu)) {
                if (first == FAST)
                        c->now--;
                else
                        c->later--;
                return true;
        }

        return false;
}
*/
/* select_cpu: CPU を決める。カーネルスレッドは基本 prev_cpu を維持 */
s32 BPF_STRUCT_OPS(prototype_select_cpu, struct task_struct *p, s32 prev_cpu,
                   u64 wake_flags)
{
/*
        if (is_kernel_kthread(p)) {
                if (cpu_online(prev_cpu))
                        return prev_cpu;

                s32 cpu = pick_idle_cpu012();
                if (cpu < 0)
                        cpu = bpf_get_smp_processor_id();
                return cpu;
        }
*/

        if (is_kernel_kthread(p)) {
                s32 want = prev_cpu;
                if (!cpu_online(want))
                        want = pick_idle_cpu012();  /* 0–2のどれか */
                if (want < 0)
                        want = bpf_get_smp_processor_id();

                /* prev_cpu==3 でも、CPU3必須でなければ 0–2 を返す */
                if (want == 3 && !kernel_task_must_run_on_cpu(p, 3)) {
                        s32 alt = pick_idle_cpu012();
                        if (alt >= 0) return alt;
                        return 0; /* 最低でも0へ */
                }
                return want;
        }

        /* 2. ユーザー空間タスク：緊急度が高ければ idle CPU をヒントに返す
         *    ※ここでは direct dispatch（scx_bpf_dsq_insert）は行わず、
         *      実際の DSQ 振り分けは enqueue に任せる。
         */
        s64 slack = task_slack_ns(p);
/*
        if (slack <= 0 || slack <= (s64)get_slack_ns()) {
                s32 cpu = pick_idle_cpu012();

                if (cpu >= 0 && cpu_online(cpu))
                        return cpu;
        }
*/

        if (slack <= 0 || slack <= (s64)get_slack_ns()) {
                /* CPU3 idle優先 → 無理なら 0–2 */
                const struct cpumask *idle = scx_bpf_get_idle_cpumask();
                if (idle) {
                        if (bpf_cpumask_test_cpu(3, idle)) {
                                scx_bpf_put_idle_cpumask(idle);
                                return 3;
                        }
                        scx_bpf_put_idle_cpumask(idle);
                }
                s32 cpu = pick_idle_cpu012();
                if (cpu >= 0 && cpu_online(cpu)) return cpu;
        }

        /* 3. それ以外は prev_cpu 維持 */
        return prev_cpu;
}


/* select_cpu: CPU を決める。カーネルスレッドは基本 prev_cpu を維持 */
/*
s32 BPF_STRUCT_OPS(prototype_select_cpu, struct task_struct *p, s32 prev_cpu,
                   u64 wake_flags)
{
        if (is_kernel_kthread(p)) {
                if (cpu_online(prev_cpu))
                        return prev_cpu;

                s32 cpu = pick_idle_cpu012();
                if (cpu < 0)
                        cpu = bpf_get_smp_processor_id();
                return cpu;
        }

        {
                s64 slack = task_slack_ns(p);

                if (slack <= 0 || slack <= (s64)get_slack_ns()) {
                        s32 cpu = pick_idle_cpu012();

                        if (cpu < 0)
                                cpu = prev_cpu;

                        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu,
                                           SCX_SLICE_DFL, 0);
                        scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
                        dsq_stats_inc(2);
                        return cpu;
                }
        }

        return prev_cpu;
}
*/
/* enqueue: DSQ への振り分け本体 */
void BPF_STRUCT_OPS(prototype_enqueue, struct task_struct *p, u64 enq_flags)
{
        /* 1. カーネルスレッドは専用 KERNEL DSQ へ */
/*
        if (is_kernel_kthread(p)) {
//              scx_bpf_dsq_insert(p, KERNEL, SCX_SLICE_DFL, enq_flags);
                s32 cpu = (s32)scx_bpf_task_cpu(p);
                if (!cpu_online(cpu)) {
                        s32 idle = pick_idle_cpu012();
                        if (idle >= 0 && cpu_online(idle))
                                cpu = idle;
                        else
                                cpu = bpf_get_smp_processor_id();
                }


        scx_bpf_dsq_insert(p, KERNEL_DSQ(cpu), SCX_SLICE_DFL, enq_flags);
        scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);

                dsq_stats_inc(3);
                return;
        }
*/

        if (is_kernel_kthread(p)) {
                s32 cpu = (s32)scx_bpf_task_cpu(p);
                if (!cpu_online(cpu))
                        cpu = bpf_get_smp_processor_id();

                if (cpu == 3 && !kernel_task_must_run_on_cpu(p, 3)) {
                        s32 alt = pick_idle_cpu012();
                        cpu = (alt >= 0) ? alt : 0;
                }

                scx_bpf_dsq_insert(p, KERNEL_DSQ(cpu), SCX_SLICE_DFL, enq_flags);
                scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
                dsq_stats_inc(3); /* kernel */
                return;
        }

        /* 2. ユーザー空間タスク：今やるべきなら FAST へ */
        if (task_is_urgent_user(p)) {
                scx_bpf_dsq_insert(p, FAST, SCX_SLICE_DFL, enq_flags);
                dsq_stats_inc(0); /* fast */
                return;
        }

        /* 3. それ以外は NORMAL へ。vtime で整列させる。 */
        dsq_stats_inc(1); /* normal */

        __u64 v = p->scx.dsq_vtime;

        if (vtime_before(v, vtime_now - SCX_SLICE_DFL))
                v = vtime_now - SCX_SLICE_DFL;

        scx_bpf_dsq_insert_vtime(p, NORMAL, SCX_SLICE_DFL, v, enq_flags);
}

/* dequeue: 今回は特に何もしない */
void BPF_STRUCT_OPS(prototype_dequeue, struct task_struct *p, u64 deq_flags)
{
        return;
}

/* dispatch: KERNEL -> FAST/NORMAL の順で吐く */
/*
void BPF_STRUCT_OPS(prototype_dispatch, s32 cpu, struct task_struct *prev)
{
        update_dsq_depth();

        {
                s32 fast_q   = scx_bpf_dsq_nr_queued(FAST);
                s32 normal_q = scx_bpf_dsq_nr_queued(NORMAL);
                s32 total_q_depth = 0;

                if (fast_q > 0)
                        total_q_depth += fast_q;
                if (normal_q > 0)
                        total_q_depth += normal_q;

                __u32 cur = g_load_stage;
                __u32 nxt = next_load_stage_hysteresis(cur, total_q_depth);

                if (nxt != cur) {
                        __u32 k = 0;
                        struct wrr_state *c;
//                      struct credit_pair *c;

                        g_load_stage = nxt;

                        c = bpf_map_lookup_elem(&credits, &k);
                        if (c)
                                c->acc = 0;
                }
        }

        __u32 slots = scx_bpf_dispatch_nr_slots();
        if (!slots)
                return;

        __u32 cap    = dispatch_cap_for_stage();
        __u32 budget = slots < cap ? slots : cap;

#pragma clang loop unroll(disable)
        while (budget > 0) {
                if (!scx_bpf_dsq_nr_queued(KERNEL))
                        break;
                if (!move_one(KERNEL))
//              if (!move_one(KERNEL, cpu))
                        break;
                budget--;
        }

        if (!budget)
                return;

        bool force_norm = false;
        bool force_fast = false;

        __u64 now = bpf_ktime_get_ns();
        __u32 k = 0;
        __u64 *ln = bpf_map_lookup_elem(&last_normal_dispatch, &k);
        __u64 *lf = bpf_map_lookup_elem(&last_fast_dispatch, &k);

        if (ln && *ln == 0)
                *ln = now;
        if (lf && *lf == 0)
                *lf = now;

        if (ln) {
                s32 dq = scx_bpf_dsq_nr_queued(NORMAL);
                __u64 depth = dq < 0 ? 0 : (__u64)dq;
                if (depth > 0 && now - *ln >= NORMAL_GUARD_NS)
                        force_norm = true;
        }
        if (lf) {
                s32 dq = scx_bpf_dsq_nr_queued(FAST);
                __u64 depth = dq < 0 ? 0 : (__u64)dq;
                if (depth > 0 && now - *lf >= FAST_GUARD_NS)
                        force_fast = true;
        }

        if (budget > 0 && force_fast) {
                if (move_one(FAST)) {
//                if (move_one(FAST, cpu)) {
                        if (lf)
                                *lf = bpf_ktime_get_ns();
                        budget--;
                }
        }

        if (!budget)
                return;

        if (budget > 0) {
                __u32 picked = PICK_NONE;
                if (!dispatch_one_wrr(force_norm, &picked))
                        return;
                __u64 t = bpf_ktime_get_ns();
                if (picked == PICK_NORMAL && ln)
                        *ln = t;
                else if (picked == PICK_FAST && lf)
                        *lf = t;
                budget--;
        }

#pragma clang loop unroll(disable)
        for (__u32 i = 0; i < budget; i++) {
                __u32 picked = PICK_NONE;
                if (!dispatch_one_wrr(false, &picked))
                        break;
                __u64 t = bpf_ktime_get_ns();
                if (picked == PICK_NORMAL && ln)
                        *ln = t;
                else if (picked == PICK_FAST && lf)
                        *lf = t;
        }
}
*/

void BPF_STRUCT_OPS(prototype_dispatch, s32 cpu, struct task_struct *prev)
{
        update_dsq_depth();

        /* FAST/NORMAL キュー深さを見て負荷ステージを更新 */
        {
                s32 fast_q   = scx_bpf_dsq_nr_queued(FAST);
                s32 normal_q = scx_bpf_dsq_nr_queued(NORMAL);
                s32 total_q_depth = 0;

                if (fast_q > 0)
                        total_q_depth += fast_q;
                if (normal_q > 0)
                        total_q_depth += normal_q;

                __u32 cur = g_load_stage;
                __u32 nxt = next_load_stage_hysteresis(cur, total_q_depth);

                if (nxt != cur) {
                        __u32 k = 0;
                        struct wrr_state *c;

                        g_load_stage = nxt;

                        /* 比率が変わるのでクレジットもリセット */
                        c = bpf_map_lookup_elem(&credits, &k);
                        if (c)
                                c->acc = 0;
                }
        }

        s32 slots = (s32)scx_bpf_dispatch_nr_slots();
        if (slots <= 0)
                return;

        /* ------------------------------------------------------------
         * 1) KERNEL DSQ を先に掃く（watchdog/irq/workqueue 対策）
         * ------------------------------------------------------------ */
/*
        s32 used = 0;

        s32 kcpu = cpu;
        if (kcpu < 0 || kcpu >= CPU_NUM)
                kcpu = (s32)bpf_get_smp_processor_id();
//        __u64 kq = KERNEL_DSQ(kcpu);
        __u64 kq = KERNEL_DSQ(cpu);

#pragma clang loop unroll(disable)
        for (s32 i = 0; i < KERNEL_DRAIN_MAX; i++) {
                if (used >= slots)
                        break;
                if (scx_bpf_dsq_nr_queued(kq) <= 0)
                        break;
                if (!move_one(kq))
                        break;
                used++;
        }
*/
        s32 used = 0;
/*
        s32 kcpu = cpu;
        if (kcpu < 0 || kcpu >= CPU_NUM)
                kcpu = (s32)bpf_get_smp_processor_id();
        __u64 kq = KERNEL_DSQ(kcpu);
*/


        s32 kcpu = cpu;
        if (kcpu < 0 || kcpu >= CPU_NUM)
                kcpu = (s32)bpf_get_smp_processor_id();
        __u64 kq = KERNEL_DSQ(kcpu);

        /* KERNEL drain policy:
         * - Drain at most min(slots/2, KERNEL_DRAIN_MAX)
         * - On CPU3, be stricter (at most 1)
         * Rationale: keep kernel progress while preserving headroom for FAST/NORMAL. */
        s32 kcap = slots / 2;
        if (kcap < 1) kcap = 1;
        if (kcap > KERNEL_DRAIN_MAX) kcap = KERNEL_DRAIN_MAX;
        if (cpu == 3 && kcap > 1) kcap = 1;

#pragma clang loop unroll(disable)
        for (s32 i = 0; i < kcap; i++) {
               if (used >= slots)
                        break;
                if (scx_bpf_dsq_nr_queued(kq) <= 0)
                        break;
                if (!move_one(kq))
                        break;
                used++;
        }
        s32 left = slots - used;
        if (left <= 0)
                return;

        /* ------------------------------------------------------------
         * 2) ユーザータスク側の dispatch 予算 (budget)
         * ------------------------------------------------------------ */
        s32 cap = (s32)dispatch_cap_for_stage();
        if (cap < 1)
                cap = 1;
        if (cap > USER_DISPATCH_MAX)
                cap = USER_DISPATCH_MAX;
        if (cap > left)
                cap = left;

        s32 budget = cap;
        if (budget <= 0)
                return;

        /* ------------------------------------------------------------
         * 3) ガード時間による force 判定
         * ------------------------------------------------------------ */
        bool force_norm = false;
        bool force_fast = false;

        __u64 now = bpf_ktime_get_ns();
        __u32 k = 0;
        __u64 *ln = bpf_map_lookup_elem(&last_normal_dispatch, &k);
        __u64 *lf = bpf_map_lookup_elem(&last_fast_dispatch, &k);

        if (ln && *ln == 0)
                *ln = now;
        if (lf && *lf == 0)
                *lf = now;

        if (ln) {
                s32 dq = scx_bpf_dsq_nr_queued(NORMAL);
                if (dq > 0 && now - *ln >= NORMAL_GUARD_NS)
                        force_norm = true;
        }
        if (lf) {
                s32 dq = scx_bpf_dsq_nr_queued(FAST);
                if (dq > 0 && now - *lf >= FAST_GUARD_NS)
                        force_fast = true;
        }

        /* ------------------------------------------------------------
         * 4) force_fast が立っていれば FAST を 1 個だけ優先
         * ------------------------------------------------------------ */
        if (force_fast && budget > 0) {
                if (move_one(FAST)) {
                        if (lf)
                                *lf = bpf_ktime_get_ns();
                        budget--;
                }
        }
        if (budget <= 0)
                return;

        /* ------------------------------------------------------------
         * 5) 残り budget 回、WRR で FAST/NORMAL を吐く
         *    1回目だけ force_norm を渡す（要件通り）
         * ------------------------------------------------------------ */
#pragma clang loop unroll(disable)
        for (s32 i = 0; i < USER_DISPATCH_MAX; i++) {
                if (i >= budget)
                        break;

                __u32 picked = PICK_NONE;
                bool fn = (i == 0) && force_norm;

                if (!dispatch_one_wrr(fn, &picked))
                        break;

                __u64 t = bpf_ktime_get_ns();
                if (picked == PICK_NORMAL && ln)
                        *ln = t;
                else if (picked == PICK_FAST && lf)
                        *lf = t;
        }
}
/*
void BPF_STRUCT_OPS(prototype_dispatch, s32 cpu, struct task_struct *prev)
{
        update_dsq_depth();

        {
                s32 fast_q   = scx_bpf_dsq_nr_queued(FAST);
                s32 normal_q = scx_bpf_dsq_nr_queued(NORMAL);
                s32 total_q_depth = 0;

                if (fast_q > 0)
                        total_q_depth += fast_q;
                if (normal_q > 0)
                        total_q_depth += normal_q;

                __u32 cur = g_load_stage;
                __u32 nxt = next_load_stage_hysteresis(cur, total_q_depth);

                if (nxt != cur) {
                        __u32 k = 0;
                        struct wrr_state *c;

                        g_load_stage = nxt;

                        c = bpf_map_lookup_elem(&credits, &k);
                        if (c)
                                c->acc = 0;
                }
        }

        s32 slots = (s32)scx_bpf_dispatch_nr_slots();
        if (slots <= 0)
                return;

        s32 moved_kernel = 0;

#pragma clang loop unroll(disable)
        for (s32 i = 0; i < KERNEL_DRAIN_MAX; i++) {
                if (i >= slots)
                        break;
                if (scx_bpf_dsq_nr_queued(KERNEL) <= 0)
                        break;
                if (!move_one(KERNEL))
                        break;
                moved_kernel++;
        }

        s32 slots_left = slots - moved_kernel;
        if (slots_left <= 0)
                return;

        s32 cap = (s32)dispatch_cap_for_stage();
        if (cap < 1)
                cap = 1;
        if (cap > USER_DISPATCH_MAX)
                cap = USER_DISPATCH_MAX;
        if (cap > slots_left)
                cap = slots_left;

        s32 budget = cap;
        if (budget <= 0)
                return;


        bool force_norm = false;
        bool force_fast = false;

        __u64 now = bpf_ktime_get_ns();
        __u32 k = 0;
        __u64 *ln = bpf_map_lookup_elem(&last_normal_dispatch, &k);
        __u64 *lf = bpf_map_lookup_elem(&last_fast_dispatch, &k);

        if (ln && *ln == 0)
                *ln = now;
        if (lf && *lf == 0)
                *lf = now;

        if (ln) {
                s32 dq = scx_bpf_dsq_nr_queued(NORMAL);
                if (dq > 0 && now - *ln >= NORMAL_GUARD_NS)
                        force_norm = true;
        }
        if (lf) {
                s32 dq = scx_bpf_dsq_nr_queued(FAST);
                if (dq > 0 && now - *lf >= FAST_GUARD_NS)
                        force_fast = true;
        }

        if (force_fast && budget > 0) {
                if (move_one(FAST)) {
                        if (lf)
                                *lf = bpf_ktime_get_ns();
                        budget--;
                }
        }
        if (budget <= 0)
                return;

#pragma clang loop unroll(disable)
        for (s32 i = 0; i < USER_DISPATCH_MAX; i++) {
                if (i >= budget)
                        break;

                __u32 picked = PICK_NONE;
                bool fn = (i == 0) && force_norm;

                if (!dispatch_one_wrr(fn, &picked))
                        break;

                __u64 t = bpf_ktime_get_ns();
                if (picked == PICK_NORMAL && ln)
                        *ln = t;
                else if (picked == PICK_FAST && lf)
                        *lf = t;
        }
}
*/
/* thermal tracepoint: 温度ステージ更新 */
SEC("tracepoint/thermal/thermal_temperature")
int tp_thermal(struct trace_event_raw_thermal_temperature *ctx)
{
        if (g_filter_tz_id >= 0 && ctx->id != g_filter_tz_id)
                return 0;

        const int temp_mC = ctx->temp;

        __u32 cur = g_stage;
        __u32 nxt = next_stage_hysteresis(cur, temp_mC,
                                          rising_degC, falling_degC);

        if (nxt != cur) {
                __u32 k = 0;
//              struct credit_pair *c;
                struct wrr_state *c;
                g_stage = nxt;

                /* 温度ステージが変わると比率も変わるのでクレジットリセット */
/*              c = bpf_map_lookup_elem(&credits, &k);
                if (c) {
                        c->now   = 0;
                        c->later = 0;
                }
*/
                c = bpf_map_lookup_elem(&credits, &k);
                if (c)
                        c->acc = 0;
        }
        return 0;
}

/* init: DSQ 作成など */
s32 BPF_STRUCT_OPS_SLEEPABLE(prototype_init)
{
//      scx_bpf_create_dsq(KERNEL, -1);

    scx_bpf_create_dsq(KERNEL_DSQ(0), -1);
    scx_bpf_create_dsq(KERNEL_DSQ(1), -1);
    scx_bpf_create_dsq(KERNEL_DSQ(2), -1);
    scx_bpf_create_dsq(KERNEL_DSQ(3), -1);
        scx_bpf_create_dsq(FAST,   -1);
        scx_bpf_create_dsq(NORMAL, -1);
        return 0;
}

/* exit: DSQ 破棄と UEI 記録 */
void BPF_STRUCT_OPS(prototype_exit, struct scx_exit_info *ei)
{
        UEI_RECORD(uei, ei);
//      scx_bpf_destroy_dsq(KERNEL);

    scx_bpf_destroy_dsq(KERNEL_DSQ(0));
    scx_bpf_destroy_dsq(KERNEL_DSQ(1));
    scx_bpf_destroy_dsq(KERNEL_DSQ(2));
    scx_bpf_destroy_dsq(KERNEL_DSQ(3));
        scx_bpf_destroy_dsq(FAST);
        scx_bpf_destroy_dsq(NORMAL);
}

/* 新規タスク初期化（今回は特に何もしない） */
s32 BPF_STRUCT_OPS(prototype_init_task, struct task_struct *p,
                   struct scx_init_task_args *args)
{
        return 0;
}

/* running: vtime_now 更新 */
void BPF_STRUCT_OPS(prototype_running, struct task_struct *p)
{
        if (time_before(vtime_now, p->scx.dsq_vtime))
                vtime_now = p->scx.dsq_vtime;
}

/* stopping: 実際に使った slice に応じて vtime を進める */
void BPF_STRUCT_OPS(prototype_stopping, struct task_struct *p, bool runnable)
{
        p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

/* enable: 有効化時に vtime_now で初期化 */
void BPF_STRUCT_OPS(prototype_enable, struct task_struct *p)
{
        p->scx.dsq_vtime = vtime_now;
}

/* SCX ops 定義 */
SCX_OPS_DEFINE(prototype_ops,
        .select_cpu = (void *)prototype_select_cpu,
        .enqueue    = (void *)prototype_enqueue,
        .dispatch   = (void *)prototype_dispatch,
        .dequeue    = (void *)prototype_dequeue,
        .init       = (void *)prototype_init,
        .init_task  = (void *)prototype_init_task,
        .exit       = (void *)prototype_exit,
        .running    = (void *)prototype_running,
        .stopping   = (void *)prototype_stopping,
        .enable     = (void *)prototype_enable,
        .flags      = 0,
        .name       = "scx_prototype");