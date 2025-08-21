// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

//#include "sched_therm_shared.h"

char LICENSE[] SEC("license") = "GPL";

#define MAX_CPUS 8

struct cpu_metric { __u32 freq_khz; __u64 ts_ns; };
//struct thermal_metric { __s32 temp_mc, temp_prev_mc; __u32 tz_id; __u64 ts_ns; };
struct thermal_metric {__u32 zone_id; __u32 zone_prev; __u32 zone_temp; };

//Map宣言
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, MAX_CPUS);
  __type(key, __u32);
  __type(value, struct cpu_metric);
} metrics_percpu SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct thermal_metric);
} thermal_metric SEC(".maps");
/*
struct  {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct policy_state_v);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} policy_state SEC(".maps");
*/

//上書き
struct cpu_frequency_args { u64 _; __u32 state; __u32 cpu_id; };
SEC("tracepoint/power/cpu_frequency")
int tp_cpu_frequency(struct cpu_frequency_args *ctx) {
  __u32 cpu = ctx->cpu_id; if (cpu >= MAX_CPUS) return 0;
  struct cpu_metric *m = bpf_map_lookup_elem(&metrics_percpu, &cpu);
  if (!m) return 0;
  m->freq_khz = ctx->state;
  m->ts_ns = bpf_ktime_get_ns();
//  m->ts_ns = ctx->cpu_id;
  return 0;
}


//struct thermal_temperature_args { u64 _; int id; int temp_prev; int temp; };
struct thermal_temperature_args { u64 _; __u32 therm_id; __u32 therm_prev; __u32 therm_temp;};
SEC("tracepoint/thermal/thermal_temperature")
int tp_thermal_temperature(struct thermal_temperature_args *ctx) {
  __u32 k = 0;
  struct thermal_metric *t = bpf_map_lookup_elem(&thermal_metric, &k);
  if(!t)return 0;


  t->zone_id   = ctx->therm_id;
  t->zone_prev = ctx->therm_prev;
  t->zone_temp = ctx->therm_temp;

/*
  t->tz_id = (__u32)ctx->id;
  t->temp_prev_mc = ctx->temp_prev;
  t->temp_mc = ctx->temp;
  t->ts_ns = bpf_ktime_get_ns();
*/
  return 0;
}
