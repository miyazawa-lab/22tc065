// SPDX-License-Identifier: GPL-2.0
// Minimal rules-based sched_ext demo (案B骨格): 5 FIFO + 共有DSQベース
// - 5本の BPF_QUEUE(FIFO) にPIDを入れる（外側は ARRAY_OF_MAPS）
// - dispatch は qmap と同様の「指数的ラウンドロビン」＋固定上限ループ
// - 温度→段階(stage 0..3) をピン済み ARRAY(1要素)から読み、簡単ルールで qidx を調整
// - 共有DSQは標準の SCX_DSQ_GLOBAL を使う（独自DSQは作らない）

#include <scx/common.bpf.h>   // struct_ops / scx_* kfunc など
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
//#include <linux/sched.h>

char _license[] SEC("license") = "GPL";

/* ---------- 調整可能な定数（rodata） ---------- */
const volatile __u64 slice_ns = 5 * 1000 * 1000ULL;  // 5ms
const volatile __u32 dsp_batch = 1;                  // まとめ出し(最小)

/* ---------- 5本のFIFO（内側マップ） & 外側 ARRAY_OF_MAPS ---------- */
struct qmap {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 4096);
    __type(value, __u32);   // PID を運ぶ
} queue0 SEC(".maps"),
  queue1 SEC(".maps"),
  queue2 SEC(".maps"),
  queue3 SEC(".maps"),
  queue4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 5);
    __type(key, int);
    __array(values, struct qmap);
} queue_arr SEC(".maps") = {
    .values = { &queue0, &queue1, &queue2, &queue3, &queue4 },
};

/* ---- ルール定義（userspaceのstruct ruleと同一レイアウトにしておく） ---- */
struct rule {
    __u32 enable, stage_mask;
    __u64 label_and, label_or, label_not;
    __s32 dsq_id, fifo_idx;
    __u32 slice_ns, reserved;
};

/* ---- inner: rules_template（ARRAY） ---- */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);      // userspace側と合わせる
    __type(key, int);
    __type(value, struct rule);
} rules_template SEC(".maps");

/* ---- outer: active_ruleset（ARRAY_OF_MAPS。key=0 に inner を差し込む） ---- */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 1);
    __type(key, int);
    __array(values, rules_template);
} active_ruleset SEC(".maps");

/* ---------- 温度段階（collector が /sys/fs/bpf/scx_rulesched/stage を更新） ---------- */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32); // 0: COOL, 1: WARM, 2: HOT, 3: CRIT
} stage SEC(".maps");

/* ---------- per-CPU dispatch 状態（qmap風） ---------- */
struct cpu_ctx {
    __u64 dsp_idx;  // 0..4 のFIFOインデックス
    __u64 dsp_cnt;  // このFIFOから残り何件出すか（2^idx）
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cpu_ctx);
} cpu_ctx_stor SEC(".maps");

/* ---------- 統計（任意） ---------- */
static __u64 nr_enqueued, nr_dispatched;

/* ---------- ルール：weight と stage から qidx を決める ---------- */
/* weight は p->scx.weight（sched_ext が渡す複合重み）。qmap と同じ粗い分割 */
static __always_inline int weight_to_idx(__u32 weight)
{
    if (weight <= 25)      return 0;
    else if (weight <= 50) return 1;
    else if (weight < 200) return 2;
    else if (weight < 400) return 3;
    else                   return 4;
}

static __always_inline int decide_queue_idx(struct task_struct *p)
{
    __u32 s = 0, *ps;
    int idx = weight_to_idx(p->scx.weight);

    // 温度段階を参照して簡単にバイアス
    ps = bpf_map_lookup_elem(&stage, &s);
    if (ps) {
        __u32 st = *ps;        // 0..3
        // 例:
        //  WARM(1): 少しだけ低いキューへ（高優先→抑制弱）
        //  HOT(2) : 中位以下へ抑制
        //  CRIT(3): 極力 0/1 に寄せる（CPUを冷やしたい前提）
        if (st == 1) {
            if (idx > 0) idx -= 1;
        } else if (st == 2) {
            if (idx > 2) idx = 2;
        } else if (st == 3) {
            if (idx > 1) idx = 1;
        }
    }
    if (idx < 0) idx = 0;
    if (idx > 4) idx = 4;
    return idx;
}

/* ---------- select_cpu：シンプルに prev を優先、空きがあればそこへ ---------- */
s32 BPF_STRUCT_OPS(rulesched_select_cpu, struct task_struct *p,
                   s32 prev_cpu, __u64 wake_flags)
{
    // prev が使えればそこ（低オーバヘッド）
    if (p->nr_cpus_allowed == 1 || scx_bpf_test_and_clear_cpu_idle(prev_cpu))
        return prev_cpu;

    // 空きCPUがあればそこへ
    s32 cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
    if (cpu >= 0)
        return cpu;

    // だめなら前回のまま
    return prev_cpu;
}

/* ---------- enqueue：PID をFIFOに積む。溢れたらグローバルDSQへ ---------- */
void BPF_STRUCT_OPS(rulesched_enqueue, struct task_struct *p, __u64 enq_flags)
{
    int idx = decide_queue_idx(p);
    void *fifo;

    // reenq（より高優先度クラスにCPUを奪われた再投入）はグローバルへ戻す
    if (enq_flags & SCX_ENQ_REENQ) {
        scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, slice_ns, enq_flags);
        // どこか空いていれば蹴って拾わせる
        s32 cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
        if (cpu >= 0) scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
        return;
    }

    fifo = bpf_map_lookup_elem(&queue_arr, &idx);
    if (!fifo) {
        scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, slice_ns, enq_flags);
        return;
    }

    __u32 pid = p->pid;
    if (bpf_map_push_elem(fifo, &pid, 0)) {
        // オーバーフロー時はグローバルへ
        scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, slice_ns, enq_flags);
        return;
    }

    __sync_fetch_and_add(&nr_enqueued, 1);
}

/* ---------- dequeue（任意の統計） ---------- */
void BPF_STRUCT_OPS(rulesched_dequeue, struct task_struct *p, __u64 deq_flags)
{
    // nothing
}

/* ---------- dispatch：qmap 同等の指数ラウンドロビン（固定上限ループ） ---------- */
void BPF_STRUCT_OPS(rulesched_dispatch, __s32 cpu, struct task_struct *prev)
{
    struct cpu_ctx *cpuc;
    __u32 zero = 0;

    // グローバルに何かあればローカルへ寄せて即return（低コスト）
    if (scx_bpf_dsq_move_to_local(SCX_DSQ_GLOBAL))
        return;

    cpuc = bpf_map_lookup_elem(&cpu_ctx_stor, &zero);
    if (!cpuc) {
        scx_bpf_error("cpu_ctx lookup failed");
        return;
    }

#pragma clang loop unroll(full)
    for (int scan = 0; scan < 5; scan++) {
        if (!cpuc->dsp_cnt) {
            cpuc->dsp_idx = (cpuc->dsp_idx + 1) % 5;
            cpuc->dsp_cnt = 1u << cpuc->dsp_idx;
        }
        int qidx = (int)cpuc->dsp_idx;
        void *fifo = bpf_map_lookup_elem(&queue_arr, &qidx);
        if (!fifo)
            break;

        bpf_repeat(BPF_MAX_LOOPS) {
            __s32 pid;
            if (bpf_map_pop_elem(fifo, &pid))
                break;

            struct task_struct *tp = bpf_task_from_pid(pid);
            if (!tp)
                continue;

            scx_bpf_dsq_insert(tp, SCX_DSQ_GLOBAL, slice_ns, 0);
            bpf_task_release(tp);
            __sync_fetch_and_add(&nr_dispatched, 1);

            if (cpuc->dsp_cnt)
                cpuc->dsp_cnt--;

            if (!scx_bpf_dispatch_nr_slots()) {
                scx_bpf_dsq_move_to_local(SCX_DSQ_GLOBAL);
                return;
            }
            if (!cpuc->dsp_cnt)
                break;
        }
    }

    // ここまでで空なら prev 継続
    return;
}

/* ---------- init_task / init / exit（最小） ---------- */
s32 BPF_STRUCT_OPS(rulesched_init_task, struct task_struct *p,
                   struct scx_init_task_args *args)
{
    return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(rulesched_init)
{
    // 独自DSQは使わない（SCX_DSQ_GLOBAL/LOCAL を利用）
    return 0;
}

void BPF_STRUCT_OPS(rulesched_exit, struct scx_exit_info *ei)
{
    // no-op
}

/* ---------- struct_ops 定義 ---------- */
SCX_OPS_DEFINE(rulesched_ops,
    .select_cpu = (void *)rulesched_select_cpu,
    .enqueue    = (void *)rulesched_enqueue,
    .dequeue    = (void *)rulesched_dequeue,
    .dispatch   = (void *)rulesched_dispatch,
    .init_task  = (void *)rulesched_init_task,
    .init       = (void *)rulesched_init,
    .exit       = (void *)rulesched_exit,
    .timeout_ms = 5000U,
    .name       = "rulesched");
