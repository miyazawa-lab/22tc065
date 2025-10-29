// scheds/c/scx_prototype.c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

#include "scx_prototype.skel.h"  // Meson(gen_bpf_skel) が生成

static volatile sig_atomic_t exiting;

static void on_signal(int sig) { (void)sig; exiting = 1; }

static int bump_memlock(void) {
    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
    return setrlimit(RLIMIT_MEMLOCK, &r);
}

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *fmt, va_list args) {
    if (level == LIBBPF_DEBUG) return 0; // noisy なら抑制
    return vfprintf(stderr, fmt, args);
}

int main(int argc, char **argv)
{
    int err = 0;
    struct scx_prototype *skel = NULL;
    struct bpf_link *link = NULL;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    if (bump_memlock()) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        // 続行は可能なので落とさない
    }

    skel = scx_prototype__open();
    if (!skel) {
        fprintf(stderr, "failed to open skeleton\n");
        return 1;
    }

    // 例: 環境変数で thermal zone を絞りたい場合
    //    export SCX_TZ_ID=10 など
    const char *tz = getenv("SCX_TZ_ID");
    if (tz) {
        int id = atoi(tz);
        // g_filter_tz_id は BPF 側で 'const volatile' → .rodata
        skel->rodata->g_filter_tz_id = id;
    }

    err = scx_prototype__load(skel);
    if (err) {
        fprintf(stderr, "failed to load skeleton: %d\n", err);
        goto out;
    }

    // struct_ops の attach（= あなたの ops をカーネルへ登録）
    // bpf_map__attach_struct_ops() の一般的な使い方
    //  ref: libbpf ドキュメント
    link = bpf_map__attach_struct_ops(skel->maps.prototype_ops);
    if (!link) {
        err = -errno;
        perror("bpf_map__attach_struct_ops");
        goto out;
    }

    printf("[scx_prototype] running. Press Ctrl-C to stop.\n");
    while (!exiting) sleep(1);

out:
    if (link) bpf_link__destroy(link);
    scx_prototype__destroy(skel);
    return err ? 1 : 0;
}
