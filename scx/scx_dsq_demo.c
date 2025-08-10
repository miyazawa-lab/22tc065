// SPDX-License-Identifier: GPL-2.0
/*
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "scx_dsq_demo.bpf.skel.h"
*/
#include <scx/common.h> 
#include <linux/types.h>        /* ← u64, s64,とかを定義 */
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "scx_dsq_demo.bpf.skel.h"//.bpfプログラムから.skelが作られる

static volatile bool exiting;

static void sigint(int sig) { exiting = true; }

int main(void)
{
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    signal(SIGINT, sigint);

//    struct scx_dsq_demo_bpf *skel = scx_dsq_demo_bpf__open_and_load();
    struct scx_dsq_demo *skel = scx_dsq_demo__open_and_load();
    if (!skel) { perror("open_and_load"); return 1; }

//    if (scx_dsq_demo_bpf__attach(skel)) { perror("attach"); goto cleanup; }
    if (scx_dsq_demo__attach(skel)) { perror("attach"); goto cleanup; }
    puts("scx_dsq_demo attached – Ctrl+C to exit");
    while (!exiting) pause();

cleanup:
    scx_dsq_demo__destroy(skel);
    return 0;
}
