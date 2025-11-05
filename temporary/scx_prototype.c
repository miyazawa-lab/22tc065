#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <linux/types.h>
#include <scx/common.h>


#include "scx_prototype.shared.h"
#include "scx_prototype.bpf.skel.h"

static volatile sig_atomic_t exiting;

static void on_signal(int sig) { (void)sig; exiting = 1; }

static int bump_memlock(void) {
    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
    return setrlimit(RLIMIT_MEMLOCK, &r);
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args) {
    if (level == LIBBPF_DEBUG)
	 return 0;
    return vfprintf(stderr, fmt, args);
}

int main(int argc, char **argv)
{
    int err = 0;
    struct scx_prototype *skel = NULL;
    struct bpf_link *ops_link = NULL;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    if (bump_memlock())
	perror("setrlimit(RLIMIT_MEMLOCK)");

    skel = scx_prototype__open();
    if (!skel) {
	fprintf(stderr, "failed to open skeleton\n");
	return 1;
    }
/*
    const char *tz = getenv("SCX_TZ_ID");
    if (tz) skel->rodata->g_filter_tz_id = atoi(tz);

    err = scx_prototype__load(skel);
    if (err) { fprintf(stderr, "failed to load skeleton: %d\n", err); goto out; }

    err = scx_prototype__attach(skel);
    if (err) { fprintf(stderr, "failed to attach programs: %d\n", err); goto out; }

//    ops_link = bpf_map__attach_struct_ops(skel->maps.prototype_ops);
//    if (!ops_link) { err = -errno; perror("bpf_map__attach_struct_ops"); goto out; }

    printf("[scx_prototype] running. Press Ctrl-C to stop.\n");
    while (!exiting) sleep(1);
*/
    int rc = bpf_map__set_autoattach(skel->maps.prototype_ops, false);
    if (rc) {
        fprintf(stderr, "bpf_map__set_autoattach(false) failed: %d\n", rc);
    }

    const char *tz = getenv("SCX_TZ_ID");
    if (tz) skel->rodata->g_filter_tz_id = atoi(tz);

    err = scx_prototype__load(skel);
    if (err) { fprintf(stderr, "failed to load skeleton: %d\n", err); goto out; }

    err = scx_prototype__attach(skel);
    if (err) { fprintf(stderr, "failed to attach (auto) programs: %d\n", err); goto out; }

    ops_link = bpf_map__attach_struct_ops(skel->maps.prototype_ops);
    if (!ops_link) {
        err = -errno;
        perror("bpf_map__attach_struct_ops");
        goto out;
    }

    printf("[scx_prototype] running. Press Ctrl-C to stop.\n");
    while (!exiting) sleep(1);
out:
    if (ops_link) bpf_link__destroy(ops_link);
    scx_prototype__destroy(skel);
    return err ? 1 : 0;
}

