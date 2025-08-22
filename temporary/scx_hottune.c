// SPDX-License-Identifier: GPL-2.0
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

#include <scx/common.h>   // ★ これを早めに
#include <linux/types.h>  // ★ skeleton 内の u64 などを解決

#include "scx_hottune.bpf.skel.h"

#define PIN_DIR "/sys/fs/bpf/scx_hottune"

int main(void)
{
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    struct scx_hottune *skel = scx_hottune__open();
    if (!skel) {
        fprintf(stderr, "open failed\n");
        return 1;
    }

    // /sys/fs/bpf/scx_hottune を用意
    if (access(PIN_DIR, F_OK) && mkdir(PIN_DIR, 0755) && errno != EEXIST) {
        perror("mkdir bpffs dir");
        return 1;
    }

    // ★ stage だけ pin する（他は pin しない）
    bpf_map__set_pin_path(skel->maps.stage, PIN_DIR "/stage");  // ← load 前に設定

    if (scx_hottune__load(skel)) {
        fprintf(stderr, "load failed\n");
        return 1;
    }

    // 初期 stage=0 を書いておく
    __u32 zero = 0, st0 = 0;
    (void)bpf_map_update_elem(bpf_map__fd(skel->maps.stage), &zero, &st0, BPF_ANY);

    // tracepoint attach（BPF 側で宣言済み）
    if (scx_hottune__attach(skel)) {
        fprintf(stderr, "attach failed\n");
        return 1;
    }

    // struct_ops をアタッチ
    struct bpf_link *link = bpf_map__attach_struct_ops(skel->maps.hottune_ops);
    if (!link) {
        perror("attach struct_ops");
        return 1;
    }

    printf("scx_hottune attached. PIN=%s\n", PIN_DIR);
    for (;;)
        pause();

    // not reached
    bpf_link__destroy(link);
    scx_hottune__destroy(skel);
    return 0;
}
