// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <scx/common.bpf.h>

#define DSQ_USER 1ULL
#define DSQ_NET  2ULL
#define DSQ_IO   3ULL //unsigned long long : u64 : 64bit符号なし整数

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} enq_cnt SEC(".maps");//Map登録

static __always_inline u64 classify(struct task_struct *p)
{
/*classify():割り振りのルール決める
今回はルールを決めてないから大半はI/O
名前以外にもIDでも決めれる
*/
//簡易的な割り振り
    char comm[TASK_COMM_LEN] = {};
    bpf_core_read_str(&comm, sizeof(comm), p->comm);

    if (!__builtin_memcmp(comm, "usr_", 4) || p->static_prio < 110)
        return DSQ_USER;
    if (!__builtin_memcmp(comm, "net_", 4))
        return DSQ_NET;
    return DSQ_IO;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(dsq_demo_init)//初期化
{
    scx_bpf_create_dsq(DSQ_USER, -1);
    scx_bpf_create_dsq(DSQ_NET,  -1);
    scx_bpf_create_dsq(DSQ_IO,   -1);
    return 0;
}
/*
s32 BPF_STRUCT_OPS_SLEEPABLE(dsq_demo_init)
{
     scx_bpf_create_dsq(DSQ_USER, -1);

}
*/
void BPF_STRUCT_OPS(dsq_demo_enqueue, struct task_struct *p, u64 enq_flags)
{
/*void BPF_STRUCT_OPS(dsq_demo_enqueue, struct task_struct *p, u64 enq_flags)
= SEC(struct_ops/dsq_demo_enqueue):struct_opsのBPFプログラム
https://docs.ebpf.io/ebpf-library/scx/BPF_STRUCT_OPS/
汎用性高い書き方
*/
/*task_struct:Linux task構造体 : プロセスの表現方法*/
    u64 dsq = classify(p);//
    scx_bpf_dsq_insert(p, dsq, SCX_SLICE_DFL, enq_flags);//タスクをDSQに入れる

    u32 idx = dsq;//
    u64 *v = bpf_map_lookup_elem(&enq_cnt, &idx);//idxが指すMap領域のポインタを返却
    if (v)
        __sync_fetch_and_add(v, 1);//v += 1;
}

//登録:Mapのそれと似た感じ
const struct sched_ext_ops dsq_demo_ops SEC(".struct_ops") = {
    .name    = "dsq_demo",//nameは必須、他は自由
    .init    = (void *)dsq_demo_init,
    .enqueue = (void *)dsq_demo_enqueue,
};
char _license[] SEC("license") = "GPL";//BPFヘルパ、kfuncを使うため
