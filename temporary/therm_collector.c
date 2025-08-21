// SPDX-License-Identifier: GPL-2.0
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>

#include "therm_collector.skel.h"

static const char *PIN_DIR      = "/sys/fs/bpf/therm_sched";
static const char *PIN_DIR_SCX  = "/sys/fs/bpf/scx_rulesched";

int main(void)
{
int err; struct therm_collector_bpf *obj;

libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
if (access(PIN_DIR, F_OK) && mkdir(PIN_DIR, 0755) && errno != EEXIST) {
perror("mkdir therm_sched"); return 1;
}

obj = therm_collector_bpf__open(); if (!obj) return 1;
if ((err = therm_collector_bpf__load(obj)))   { fprintf(stderr, "load\n");   return err; }
if ((err = therm_collector_bpf__attach(obj))) { fprintf(stderr, "attach\n"); return err; }

/* 一括 pin */
if (bpf_object__pin_maps(obj->obj, PIN_DIR)) {
fprintf(stderr, "pin maps failed\n"); return 1;
}

/* scx_rulesched の stage マップを開く */
int stage_fd = bpf_obj_get("/sys/fs/bpf/scx_rulesched/stage");
if (stage_fd < 0) { perror("open stage map"); return 1; }

/* 自分が pin した温度マップを開く */
int therm_fd = bpf_obj_get("/sys/fs/bpf/therm_sched/thermal_metric");
if (therm_fd < 0) { perror("open thermal_metric"); return 1; }

puts("collector attached. updating stage...");

/* 200ms 間隔で温度を読み、stage を更新 */
for (;;) {
struct { __u32 zone_id, zone_prev, zone_temp; } t = {0};
__u32 k = 0, st = 0;

if (bpf_map_lookup_elem(therm_fd, &k, &t) == 0) {
int c = (int)(t.zone_temp / 1000); /* milli-C → C */
if      (c >= 85) st = 3; /* CRIT */
else if (c >= 79) st = 2; /* HOT  */
else if (c >= 75) st = 1; /* WARM */
else              st = 0; /* COOL */

bpf_map_update_elem(stage_fd, &k, &st, BPF_ANY);
}

struct timespec ts = {.tv_sec=0, .tv_nsec=200*1000*1000};
nanosleep(&ts, NULL);
}

/* not reached */
therm_collector_bpf__destroy(obj);
return 0;
}
