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

s32 BPF_STRUCT_OPS(prototype_select_cpu, struct *p, s32 prev_cpu, u64 wake_flags)
{

    classify_task(p );
}

void BPF_STRUCT_OPS(prototype_enqueue, struct task_struct *p, u64 enq_flags)
{

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
