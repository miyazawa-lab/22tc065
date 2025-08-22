// SPDX-License-Identifier: GPL-2.0
// scx_hottune: PELT(util) + burstiness + weight を合成し、温度 stage で dispatch を縮退
// 依存: Linux sched_ext (struct_ops), thermal tracepoint, CO-RE(BTF)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <scx/common.bpf.h>   // sched_ext kfuncs / struct_ops

char _license[] SEC("license") = "GPL";

/* ----- 古い環境向けフォールバック: bpf_map_lookup_or_try_init ----- */
#ifndef bpf_map_lookup_or_try_init
static __always_inline void *bpf_map_lookup_or_try_init(void *map,
                                                        const void *key,
                                                        const void *init)
{
    void *val = bpf_map_lookup_elem(map, key);
    if (val)
        return val;
    bpf_map_update_elem(map, key, init, BPF_NOEXIST);
    return bpf_map_lookup_elem(map, key);
}
#endif

/* ---------- 定数（rodata） ---------- */
const volatile __u64 slice_ns_base[4] = {
    5*1000*1000ULL,  // COOL
    3*1000*1000ULL,  // WARM
    2*1000*1000ULL,  // HOT
    1*1000*1000ULL   // CRIT
};
const volatile __u32 qcap_by_stage[4] = {5, 5, 3, 2}; // 見るFIFO本数
/*
const volatile __u32 temp_up[4] = { 0, 75, 79, 85 };  // ℃: 昇温閾値
const volatile __u32 temp_dn[4] = { 0, 72, 76, 82 };  // ℃: 降温戻り閾値(ヒステリシス)
*/
const volatile __u32 temp_up[4] = { 0, 68, 72, 76 };  // ℃: 昇温閾値
const volatile __u32 temp_dn[4] = { 0, 65, 70, 74 };  // ℃: 降温戻り閾値(ヒステリシス)

/* ---------- 5本FIFO + AoM ---------- */
struct qmap {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 4096);
    __type(value, __u32);  // PID
} queue0 SEC(".maps"), queue1 SEC(".maps"), queue2 SEC(".maps"),
  queue3 SEC(".maps"), queue4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 5);
    __type(key, int);
    __array(values, struct qmap);
} queue_arr SEC(".maps") = {
    .values = { &queue0, &queue1, &queue2, &queue3, &queue4 },
};

/* ---------- 温度stage (0..3) をBPF内で決定 ---------- */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} stage SEC(".maps");

/* ---------- per-CPU dispatch 状態 ---------- */
struct cpu_ctx { __u64 dsp_idx; __u64 dsp_cnt; };
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cpu_ctx);
} cpu_ctx_stor SEC(".maps");

/* ---------- burstiness (多wake) 推定: LRU_HASH (pid→EWMA) ---------- */
struct burst_stat { __u32 ewma; __u64 last_ts; };
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, struct burst_stat);
} burst SEC(".maps");

static __always_inline void burst_touch(__u32 pid)
{
    struct burst_stat zero = {};
    struct burst_stat *bs = bpf_map_lookup_or_try_init(&burst, &pid, &zero);
    if (!bs) return;

    // およそ 32ms ごとに 1bit 減衰させる簡易 EWMA
    __u64 now = bpf_ktime_get_ns();
    __u64 last = bs->last_ts;
    bs->last_ts = now;

    if (last) {
        __u64 dt = now - last;
        __u32 steps = dt / 32000000ULL;   // 32ms
        if (steps > 8) steps = 8;
        if (steps) bs->ewma >>= steps;
    }
    // 入力は unit=256 で積み上げ（固定小数）
    bs->ewma += 256;
    if (bs->ewma > (256u * 1024u)) bs->ewma = 256u * 1024u; // clamp
}

/* ---------- util_avg(0..1024) を読む（CO-RE） ---------- */
static __always_inline __u32 task_util_avg(const struct task_struct *p)
{
    __u32 util = 0;
    bpf_core_read(&util, sizeof(util), &p->se.avg.util_avg);
    if (util > 1024) util = 1024;
    return util;
}

/* ---------- 合成スコア → 5段化 ---------- */
static __always_inline int score_to_idx(__u32 util, __u32 burst256, __u32 w)
{
    // 正規化（0..1024）
    __u32 util_n   = util;                // 0..1024
    __u32 burst_n  = burst256 >> 8;       // 0..1024 目安
    __u32 weight_n = w; if (weight_n > 10000) weight_n = 10000;
    weight_n = (weight_n * 1024) / 10000; // 0..1024

    // 係数: 0.45, 0.35, 0.20（*1024 スケール）
    __u32 score = (util_n * 461 + burst_n * 358 + weight_n * 205) / 1024;

    // 固定分位点
    if (score <= 256)  return 0;
    if (score <= 512)  return 1;
    if (score <= 768)  return 2;
    if (score <= 896)  return 3;
    return 4;
}

static __always_inline int decide_queue_idx(struct task_struct *p)
{
    __u32 pid = p->pid;
    __u32 util = task_util_avg(p);
    __u32 burst_n = 0;
    struct burst_stat *bs = bpf_map_lookup_elem(&burst, &pid);
    if (bs) burst_n = bs->ewma;

    return score_to_idx(util, burst_n, p->scx.weight);
}

/* ---------- select_cpu：prev / idle を優先 ---------- */
s32 BPF_STRUCT_OPS(hottune_select_cpu, struct task_struct *p,
                   s32 prev_cpu, __u64 wake_flags)
{
    if (p->nr_cpus_allowed == 1 || scx_bpf_test_and_clear_cpu_idle(prev_cpu))
        return prev_cpu;

    s32 cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
    if (cpu >= 0) return cpu;
    return prev_cpu;
}

/* ---------- enqueue：PID を選んだFIFOへ。溢れたらグローバル ---------- */
void BPF_STRUCT_OPS(hottune_enqueue, struct task_struct *p, __u64 enq_flags)
{
    __u32 s_key = 0, st = 0;
    __u32 *pst = bpf_map_lookup_elem(&stage, &s_key);
    if (pst) st = *pst;

    /* st を 0..3 に畳み、slice を “定数オフセット” で読む（verifier対策） */
    __u64 slice_ns;
    switch (st) {
    case 0:  slice_ns = slice_ns_base[0]; break;
    case 1:  slice_ns = slice_ns_base[1]; break;
    case 2:  slice_ns = slice_ns_base[2]; break;
    default: slice_ns = slice_ns_base[3]; break;
    }

    // REENQ は即グローバルへ戻す
    if (enq_flags & SCX_ENQ_REENQ) {
        scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, slice_ns, enq_flags);
        s32 cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
        if (cpu >= 0) scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
        return;
    }

    int idx = decide_queue_idx(p);
    /* idx を 0..4 に clamp してから AoM を引く（verifier対策） */
    __u32 uidx = idx < 0 ? 0u : (idx > 4 ? 4u : (__u32)idx);

    void *fifo = bpf_map_lookup_elem(&queue_arr, &uidx);
    if (!fifo) {
        scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, slice_ns, enq_flags);
        return;
    }

    __u32 pid = p->pid;
    if (bpf_map_push_elem(fifo, &pid, BPF_ANY)) {  // 満杯なら失敗（BPF_ANY=0）
        scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, slice_ns, enq_flags);
        return;
    }

    // burstiness（多wake）更新
    burst_touch(pid);
}

void BPF_STRUCT_OPS(hottune_dequeue, struct task_struct *p, __u64 deq_flags) {}

/* ---------- dispatch：stage-aware（本数縮退＋吐き量＋slice） ---------- */
void BPF_STRUCT_OPS(hottune_dispatch, __s32 cpu, struct task_struct *prev)
{
    __u32 key0 = 0;
    struct cpu_ctx *cpuc = bpf_map_lookup_elem(&cpu_ctx_stor, &key0);
    if (!cpuc) return;

    // stage と slice を安全に取得
    __u32 st = 0, *pst = bpf_map_lookup_elem(&stage, &key0);
    if (pst) st = *pst;

    __u64 slice_ns;
    switch (st) {
    case 0:  slice_ns = slice_ns_base[0]; break;
    case 1:  slice_ns = slice_ns_base[1]; break;
    case 2:  slice_ns = slice_ns_base[2]; break;
    default: slice_ns = slice_ns_base[3]; break;
    }

    // GLOBAL に何かあれば LOCAL へ寄せて即 return
    if (scx_bpf_dsq_move_to_local(SCX_DSQ_GLOBAL))
        return;

    // 見るキュー本数（HOT=3, CRIT=2）: 定数オフセットで読む
    __u32 qcap;
    switch (st) {
    case 0:  qcap = qcap_by_stage[0]; break;
    case 1:  qcap = qcap_by_stage[1]; break;
    case 2:  qcap = qcap_by_stage[2]; break;
    default: qcap = qcap_by_stage[3]; break;
    }
    if (qcap < 2) qcap = 2;
    if (qcap > 5) qcap = 5;
    cpuc->dsp_idx %= qcap;

#pragma unroll
    for (int scan = 0; scan < 5; scan++) { // 実際には qcap 回だけ回す
        if (scan >= qcap) break;

        if (!cpuc->dsp_cnt) {
            cpuc->dsp_idx = (cpuc->dsp_idx + 1) % qcap;

            __u64 base = 1ull << cpuc->dsp_idx;   // 指数RR（qmap 骨格）
            if (st == 2 && base > 1) base >>= 1;  // HOT: 半減
            if (st == 3) base = 1;                // CRIT: 最小
            cpuc->dsp_cnt = base;
        }

        // AoM 参照前に clamp（verifier対策）
        __u32 qidx = cpuc->dsp_idx;
        if (qidx > 4) qidx = 4;

        void *fifo = bpf_map_lookup_elem(&queue_arr, &qidx);
        if (!fifo) break;

        bpf_repeat(BPF_MAX_LOOPS) {
            __u32 pid;
            if (bpf_map_pop_elem(fifo, &pid))
                break;

            struct task_struct *tp = bpf_task_from_pid(pid);
            if (!tp) continue;

            scx_bpf_dsq_insert(tp, SCX_DSQ_GLOBAL, slice_ns, 0);
            bpf_task_release(tp);

            if (cpuc->dsp_cnt) cpuc->dsp_cnt--;

            if (!scx_bpf_dispatch_nr_slots()) {
                scx_bpf_dsq_move_to_local(SCX_DSQ_GLOBAL);
                return;
            }
            if (!cpuc->dsp_cnt) break;
        }
    }
}

/* ---------- thermal: 温度→stage（ヒステリシス付き） ---------- */
/* tracepoint フィールド: (id, temp_prev, temp) は m℃ */
struct tp_thermal_args { u64 _; int id; int temp_prev; int temp; };
SEC("tracepoint/thermal/thermal_temperature")
int tp_thermal(struct tp_thermal_args *ctx)
{
    __u32 k = 0;
    __u32 *pst = bpf_map_lookup_elem(&stage, &k);
    __u32 st = pst ? *pst : 0;

    // m℃ のまま比較（除算しない）
    __u32 t_mc = (__u32)ctx->temp;
    __u32 next = st;

    if      (t_mc >= temp_up[3] * 1000u) next = 3;
    else if (t_mc >= temp_up[2] * 1000u) next = (st >= 3 && t_mc > temp_dn[3] * 1000u) ? st : 2;
    else if (t_mc >= temp_up[1] * 1000u) next = (st >= 2 && t_mc > temp_dn[2] * 1000u) ? st : 1;
    else if (t_mc <= temp_dn[1] * 1000u) next = 0;

    if (!pst || *pst != next)
        bpf_map_update_elem(&stage, &k, &next, BPF_ANY);
    return 0;
}

/* ---------- init/exit ---------- */
s32 BPF_STRUCT_OPS(hottune_init_task, struct task_struct *p,
                   struct scx_init_task_args *args) { return 0; }

s32 BPF_STRUCT_OPS_SLEEPABLE(hottune_init)
{
    // 独自DSQは使わず GLOBAL/LOCAL を利用（FIFO）
    return 0;
}

void BPF_STRUCT_OPS(hottune_exit, struct scx_exit_info *ei) {}

/* ---------- struct_ops ---------- */
SCX_OPS_DEFINE(hottune_ops,
    .select_cpu = (void *)hottune_select_cpu,
    .enqueue    = (void *)hottune_enqueue,
    .dequeue    = (void *)hottune_dequeue,
    .dispatch   = (void *)hottune_dispatch,
    .init_task  = (void *)hottune_init_task,
    .init       = (void *)hottune_init,
    .exit       = (void *)hottune_exit,
    .timeout_ms = 5000U,
    .name       = "scx_hottune");
