// userspace loader for scx_rulesched

#include <scx/common.h>                    // ← これを一番最初に
#include "scx_rulesched.bpf.skel.h"        // ← スケルトン名は .bpf.skel.h

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#define PIN_DIR "/sys/fs/bpf/scx_rulesched"

struct rule {
    __u32 enable, stage_mask;
    __u64 label_and, label_or, label_not;
    __s32 dsq_id, fifo_idx;
    __u32 slice_ns, reserved;
};

static int mkdir_pindir(void) {
    if (access(PIN_DIR, F_OK) == 0) return 0;
    if (mkdir(PIN_DIR, 0755) && errno != EEXIST) {
        perror("mkdir PIN_DIR"); return -1;
    }
    return 0;
}

/* libbpf の bpf_map_create() を使って内側 ARRAY を作る */
static int create_inner_rules_map(const struct bpf_map *tmpl)
{
    struct bpf_map_create_opts opts = {
        .sz = sizeof(opts),
        // 念のためテンプレートのフラグを踏襲（通常は0のままでも可）
        .map_flags = bpf_map__map_flags(tmpl),
    };
    int fd = bpf_map_create(
        bpf_map__type(tmpl),            /* BPF_MAP_TYPE_ARRAY */
        "rules_inner",
        bpf_map__key_size(tmpl),        /* u32 */
        bpf_map__value_size(tmpl),      /* struct rule */
        bpf_map__max_entries(tmpl),     /* 64 など */
        &opts
    );
    if (fd < 0) perror("bpf_map_create(inner rules)");
    return fd;
}

static void put_sample_rules(int inner_fd)
{
    struct rule r = {0};

    /* 例1: COOL/WARM & (label bit0) → DSQ_USER(=2) */
    r.enable=1; r.stage_mask=(1u<<0)|(1u<<1); r.label_and=1ULL<<0;
    r.dsq_id=2; r.fifo_idx=-1; r.slice_ns=5*1000*1000;
    bpf_map_update_elem(inner_fd, &(int){0}, &r, BPF_ANY);

    /* 例2: HOT & !(bit3) → FIFO2 */
    memset(&r, 0, sizeof(r));
    r.enable=1; r.stage_mask=(1u<<2); r.label_not=1ULL<<3;
    r.dsq_id=-1; r.fifo_idx=2; r.slice_ns=5*1000*1000;
    bpf_map_update_elem(inner_fd, &(int){1}, &r, BPF_ANY);

    /* 例3: CRIT → DSQ_LOWPRI(=3) */
    memset(&r, 0, sizeof(r));
    r.enable=1; r.stage_mask=(1u<<3);
    r.dsq_id=3; r.fifo_idx=-1; r.slice_ns=2*1000*1000;
    bpf_map_update_elem(inner_fd, &(int){2}, &r, BPF_ANY);
}

int main(void)
{
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    if (mkdir_pindir()) return 1;

    /* スケルトンの関数名は <name>__open()/__load() です */
    struct scx_rulesched *skel = scx_rulesched__open();
    if (!skel) { fprintf(stderr, "open failed\n"); return 1; }

    if (scx_rulesched__load(skel)) {
        fprintf(stderr, "load failed\n"); return 1;
    }

    /* ルール束(inner array)を作って outer AoM の key=0 にセット */
    const struct bpf_map *tmpl = skel->maps.rules_template;
    int inner_fd = create_inner_rules_map(tmpl);
    if (inner_fd < 0) return 1;
    put_sample_rules(inner_fd);

    int outer_fd = bpf_map__fd(skel->maps.active_ruleset);
    __u32 k0 = 0;
    if (bpf_map_update_elem(outer_fd, &k0, &inner_fd, BPF_ANY)) {
        perror("active_ruleset update"); return 1;
    }

    /* マップを pin（labels, stage, active_ruleset など） */
    if (bpf_object__pin_maps(skel->obj, PIN_DIR)) {
        fprintf(stderr, "pin maps failed\n"); return 1;
    }

    /* struct_ops をアタッチ */
    struct bpf_link *link = bpf_map__attach_struct_ops(skel->maps.rulesched_ops);
    if (!link) { perror("attach struct_ops"); return 1; }

    printf("rulesched attached. PIN=%s\n", PIN_DIR);
    for (;;) pause();

    /* 後始末(到達しない想定) */
    bpf_link__destroy(link);
    scx_rulesched__destroy(skel);
    return 0;
}
