/*
  Copyright 2015 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - high-performance binary-only instrumentation
   -----------------------------------------------------------------

   Written by Andrew Griffiths <agriffiths@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   Idea & design very much by Andrew Griffiths.

   This code is a shim patched into the separately-distributed source
   code of QEMU 2.10.0. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting QEMU binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.
*/

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/shm.h>
#include <unistd.h>
#include "../../config.h"

/***************************
 * VARIOUS AUXILIARY STUFF *
 ***************************/

/* A snippet patched into tb_find_slow to inform the parent process that
   we have hit a new block that hasn't been translated yet, and to tell
   it to translate within its own context, too (this avoids translation
   overhead in the next forked-off copy). */

#define AFL_QEMU_CPU_SNIPPET1 do { \
    afl_request_tsl(pc, cs_base, flags); \
  } while (0)

/* This snippet kicks in when the instruction pointer is positioned at
   _start and does the usual forkserver stuff, not very different from
   regular instrumentation injected via afl-as.h. */
/* itb->pc指向本Block转换后可以在本机上直接执行的机器码，可以认为是该Block的实际地址 */
#define AFL_QEMU_CPU_SNIPPET2 do { \
    if(itb->pc == afl_entry_point) { \
      afl_setup(); \
      afl_forkserver(cpu); \
    } \
    afl_maybe_log(itb->pc, cpu); \
  } while (0)

static void append_debug(const char* format, ...)
{
  if (getenv("DEBUG_FILE")) {
    char* debug_file = getenv("DEBUG_FILE");
    // 打开文件以追加写入
    FILE* file = fopen(debug_file, "a");
    if (file == NULL) {
        fprintf(stderr, "无法打开debug_file: %s\n", debug_file);
        return;
    }

    // 格式化字符串
    va_list args;
    va_start(args, format);
    char buffer[256];  // 假设最大长度为256
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    // 写入文件
    fprintf(file, "%s", buffer);

    // 关闭文件
    fclose(file);
  } else return;    
}

/* We use one additional file descriptor to relay "needs translation"
   messages between the child and the fork server. */

#define TSL_FD (FORKSRV_FD - 1)

/* This is equivalent to afl-as.h: */

static unsigned char *afl_area_ptr;

/* Exported variables populated by the code patched into elfload.c: */

abi_ulong afl_entry_point, /* ELF entry point (_start) */
          afl_start_code,  /* .text start pointer      */
          afl_end_code,    /* .text end pointer        */
          afl_exit_addr = 0;    /* target program main + offset address for segmentation */

/* Set in the child process in forkserver mode: */

static unsigned char afl_fork_child;
unsigned int afl_forksrv_pid;

/* Instrumentation ratio: */

static unsigned int afl_inst_rms = MAP_SIZE;

/* Function declarations. */
static void afl_seg_offset(void);
static void afl_setup(void);
static void afl_forkserver(CPUState*);
static inline void afl_maybe_log(abi_ulong, CPUState*);
// static void afl_get_addr(abi_ulong);

static void afl_wait_tsl(CPUState*, int);
static void afl_request_tsl(target_ulong, target_ulong, uint64_t);

/* Data structure passed around by the translate handlers: */

struct afl_tsl {
  target_ulong pc;
  target_ulong cs_base;
  uint64_t flags;
};

/* Some forward decls: */

TranslationBlock *tb_htable_lookup(CPUState*, target_ulong, target_ulong, uint32_t);
static inline TranslationBlock *tb_find(CPUState*, TranslationBlock*, int);

/*************************
 * ACTUAL IMPLEMENTATION *
 *************************/

/* Set up SHM region and initialize other stuff. */

static void afl_setup(void) {
  // 获取提前放入环境变量的共享内存id
  char *id_str = getenv(SHM_ENV_VAR),
       *inst_r = getenv("AFL_INST_RATIO");

  int shm_id;
  /* 决定插桩的“密度”，后面会提到 */
  if (inst_r) {

    unsigned int r;

    r = atoi(inst_r);

    if (r > 100) r = 100;
    if (!r) r = 1;

    afl_inst_rms = MAP_SIZE * r / 100;

  }

  if (id_str) {
    /* 获取共享内存地址 */
    shm_id = atoi(id_str);
    afl_area_ptr = shmat(shm_id, NULL, 0);

    if (afl_area_ptr == (void*)-1) exit(1);

    /* With AFL_INST_RATIO set to a low value, we want to touch the bitmap
       so that the parent doesn't give up on us. */

    if (inst_r) afl_area_ptr[0] = 1;


  }

  if (getenv("AFL_INST_LIBS")) {
    /* 为动态链接库插桩 */
    afl_start_code = 0;
    afl_end_code   = (abi_ulong)-1;

  }

  afl_seg_offset();

  /* pthread_atfork() seems somewhat broken in util/rcu.c, and I'm
     not entirely sure what is the cause. This disables that
     behaviour, and seems to work alright? */

  rcu_disable_atfork();

}


/* Fork server logic, invoked once we hit _start. */

static void afl_forkserver(CPUState *cpu) {

  static unsigned char tmp[4];
  /* 保证共享内存已经初始化 */
  if (!afl_area_ptr) return;

  /* Tell the parent that we're alive. If the parent doesn't want
     to talk, assume that we're not running in forkserver mode. */
  /* 通过检查FORKSRV_FD + 1是否可写来确定本进程是否是一个AFL进程运行起来的 */
  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  afl_forksrv_pid = getpid();

  /* All right, let's await orders... */

  while (1) {

    pid_t child_pid;
    int status, t_fd[2];

    /* Whoops, parent dead? */
    /* 尝试从FORKSRV_FD读取4个字节，若读取成功，说明AFL进程告知server需要起一个新的子进程，我们在配置好管道后执行fork操作 */
    if (read(FORKSRV_FD, tmp, 4) != 4) exit(2);

    /* Establish a channel with child to grab translation commands. We'll
       read from t_fd[0], child will write to TSL_FD. */

    if (pipe(t_fd) || dup2(t_fd[1], TSL_FD) < 0) exit(3);
    close(t_fd[1]);

    child_pid = fork();
    if (child_pid < 0) exit(4);

    if (!child_pid) {
      /* 在fork出来的子进程中，关闭不需要的文件描述符，然后直接return到qemu的main loop，执行目标程序 */
      /* Child process. Close descriptors and run free. */

      afl_fork_child = 1;
      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);
      close(t_fd[0]);
      return;

    }

    /* Parent. */

    close(TSL_FD);
    /* 在server进程中，我们通过管道告知AFL进程新创建的子进程的pid */
    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) exit(5);

    /* Collect translation requests until child dies and closes the pipe. */

    afl_wait_tsl(cpu, t_fd[0]);

    /* Get and relay exit status to parent. */
    /* 获取到子进程的退出状态并反馈给AFL进程 */
    if (waitpid(child_pid, &status, 0) < 0) {
      append_debug("waitpid get child[%d] status: %d\n", child_pid, status);
      exit(6);
    }
    if (write(FORKSRV_FD + 1, &status, 4) != 4) {
      append_debug("write child[%d] status: %d\n", child_pid, status);
      exit(7);
    }
    
    append_debug("child[%d] exit with status: %d\n", child_pid, status);

  }

}


/* The equivalent of the tuple logging routine from afl-as.h. */
/* 插桩的函数 */
static inline void afl_maybe_log(abi_ulong cur_loc, CPUState *cpu) {
  // 注意这是一个静态变量
  static __thread abi_ulong prev_loc;
  abi_ulong cur_local = cur_loc;

  /* Optimize for cur_loc > afl_end_code, which is the most likely case on
     Linux systems. */
  /**
   * cur_loc是当前block的地址
   * afl_end_code是.text section的结束地址
   * afl_start_code是.text section的起始地址
   * afl_area_ptr是共享内存区（十分重要，后面会提到）
   */
  if (cur_loc > afl_end_code || cur_loc < afl_start_code || !afl_area_ptr)
    return;

  /* Looks like QEMU always maps to fixed locations, so ASAN is not a
     concern. Phew. But instruction addresses may be aligned. Let's mangle
     the value to get something quasi-uniform. */ 
  cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAP_SIZE - 1;

  /* Implement probabilistic instrumentation by looking at scrambled block
     address. This keeps the instrumented locations stable across runs. */

  if (cur_loc >= afl_inst_rms) return;

  afl_area_ptr[cur_loc ^ prev_loc]++;
  prev_loc = cur_loc >> 1;
  append_debug("Child [%d] reach2 cur_local:%u, cur:%u, main+offset:%u, reach? %d\n", getpid(), cur_local, cur_loc, afl_exit_addr, ((int)afl_exit_addr == (int)cur_local) ? 1 : 0);

  /* 如果分段偏移量不为0，证明设置了偏移，检测cur_loc是否运行到main start + offset */  
  if (afl_exit_addr && (int)afl_exit_addr == (int)cur_local) {
    // main return point
    if (1 == (int)afl_exit_addr) return;
    
    append_debug("Child [%d] reach seg. cur_local:%u, cur:%u, main+offset:%u\n", getpid(), cur_local, cur_loc, afl_exit_addr);
    CPUClass *cc = CPU_GET_CLASS(cpu);
    cc->cpu_exec_exit(cpu);
    rcu_read_unlock();
    /* 到达分段地址，子进程直接结束 */
    exit(0);    
  }

}


/* This code is invoked whenever QEMU decides that it doesn't have a
   translation of a particular block and needs to compute it. When this happens,
   we tell the parent to mirror the operation, so that the next fork() has a
   cached copy. */

static void afl_request_tsl(target_ulong pc, target_ulong cb, uint64_t flags) {

  struct afl_tsl t;

  if (!afl_fork_child) return;

  t.pc      = pc;
  t.cs_base = cb;
  t.flags   = flags;

  if (write(TSL_FD, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
    return;

}

/* This is the other side of the same channel. Since timeouts are handled by
   afl-fuzz simply killing the child, we can just wait until the pipe breaks. */

static void afl_wait_tsl(CPUState *cpu, int fd) {

  struct afl_tsl t;
  TranslationBlock *tb;

  while (1) {

    /* Broken pipe means it's time to return to the fork server routine. */

    if (read(fd, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
      break;

    tb = tb_htable_lookup(cpu, t.pc, t.cs_base, t.flags);

    if(!tb) {
      mmap_lock();
      tb_lock();
      tb_gen_code(cpu, t.pc, t.cs_base, t.flags, 0);
      mmap_unlock();
      tb_unlock();
    }

  }

  close(fd);

}

static void afl_seg_offset() {
  // 打开文件以读取数据
  FILE* file = fopen("/tmp/aflsegment", "rb");
  if (file == NULL) {
      perror("Error opening file");
      return;
  }  
  // 从文件中读取数据到变量中
  fscanf(file, "%lu", &afl_exit_addr);
  // 关闭文件
  fclose(file);  
  // 删除文件
  remove("/tmp/aflsegment");
}