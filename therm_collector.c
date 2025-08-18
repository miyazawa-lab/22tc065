#include <bpf/libbpf.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include "therm_collector.skel.h"

static const char *PIN_DIR = "/sys/fs/bpf/therm_sched";

int main(void) {
  int err; struct therm_collector_bpf *obj;

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
  if (access(PIN_DIR, F_OK) && mkdir(PIN_DIR, 0755) && errno != EEXIST) {
    perror("mkdir"); return 1;
  }

  obj = therm_collector_bpf__open(); if (!obj) return 1;
  if ((err = therm_collector_bpf__load(obj))) return err;
  if ((err = therm_collector_bpf__attach(obj))) return err;

/*
  bpf_map__set_pin_path(obj->maps.metrics_percpu, PIN_DIR);
  bpf_map__pin(obj->maps.metrics_percpu, PIN_DIR);
  bpf_map__set_pin_path(obj->maps.thermal_metric, PIN_DIR);
  bpf_map__pin(obj->maps.thermal_metric, PIN_DIR);
*/
//一括ピン
  bpf_object__pin_maps(obj->obj, PIN_DIR);

  puts("collector attached."); for (;;){ pause(); }
}
