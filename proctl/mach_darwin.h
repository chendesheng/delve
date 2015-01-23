#ifndef DARWIN_H
#define DARWIN_H

#include <mach/mach.h>
#include <stdio.h>

typedef x86_thread_state64_t Regs;
typedef unsigned long ulong;

int gettask(int pid, int* task);
//int getthreads(int task, void* threads, int* cnt);
int getregs(int tid, Regs* regs);
int setregs(int tid, Regs* regs);
int vmread(int pid, ulong addr, int size, void* data, ulong* outsz);
int vmwrite(int pid, ulong addr, void* data, int sz);
int attach(int pid, void* ths, int* nth);
int detach(int pid);
void server();
int threadresume(int tid);

#endif
