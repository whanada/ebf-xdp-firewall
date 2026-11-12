// SPDX-License-Identifier: GPL-2.0
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
static volatile sig_atomic_t stop;
static void halt(int sig) { (void)sig; stop = 1; }
int main(int argc, char **argv) {
 if (argc != 5) { fprintf(stderr, "usage: loader OBJECT INTERFACE PIN_DIR native|generic\n"); return 2; }
 if (strcmp(argv[4], "native") && strcmp(argv[4], "generic")) return 2;
 unsigned idx = if_nametoindex(argv[2]);
 if (!idx) { perror("interface"); return 1; }
 LIBBPF_OPTS(bpf_object_open_opts, opts, .pin_root_path = argv[3]);
 struct bpf_object *obj = bpf_object__open_file(argv[1], &opts);
 if (libbpf_get_error(obj)) { fprintf(stderr, "open BPF object failed\n"); return 1; }
 if (bpf_object__load(obj)) { fprintf(stderr, "verifier/load failed\n"); return 1; }
 if (bpf_object__pin_maps(obj, argv[3])) { fprintf(stderr, "pin maps failed; use a fresh pin directory\n"); return 1; }
 int fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "ingress"));
 __u32 mode = !strcmp(argv[4], "native") ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
 if (bpf_xdp_attach(idx, fd, mode | XDP_FLAGS_UPDATE_IF_NOEXIST, NULL)) {
  fprintf(stderr, "XDP attach failed; no automatic fallback\n"); return 1;
 }
 struct bpf_prog_info info = {}; __u32 len = sizeof(info);
 if (bpf_obj_get_info_by_fd(fd, &info, &len)) return 1;
 LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = idx, .attach_point = BPF_TC_EGRESS);
 int err = bpf_tc_hook_create(&hook);
 if (err && err != -EEXIST) goto detach;
 LIBBPF_OPTS(bpf_tc_opts, tc, .prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "egress")), .handle = 0x5844, .priority = 49152);
 err = bpf_tc_attach(&hook, &tc);
 if (err) goto detach;
 signal(SIGINT, halt); signal(SIGTERM, halt);
 puts("READY"); fflush(stdout);
 while (!stop) sleep(1);
 tc.flags = 0; tc.prog_fd = 0; tc.prog_id = 0;
 bpf_tc_detach(&hook, &tc);
 err = 0;
detach:;
 __u32 current = 0;
 bpf_xdp_query_id(idx, mode, &current);
 if (current == info.id) bpf_xdp_detach(idx, mode, NULL);
 bpf_object__close(obj);
 return err ? 1 : 0;
}
