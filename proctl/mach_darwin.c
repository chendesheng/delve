#include "mach_darwin.h"
#include "_cgo_export.h"

//#include   <unistd.h>
//#define USED(v)


enum {
        ExcMask = EXC_MASK_BAD_ACCESS |
                EXC_MASK_BAD_INSTRUCTION |
                EXC_MASK_ARITHMETIC |
                EXC_MASK_BREAKPOINT |
                EXC_MASK_SOFTWARE
};

static mach_port_t excport = 0;

#define CHECK_KRET(a) if ((a) != KERN_SUCCESS) {\
        printf("line %d: kernal failed with message %s!\n", __LINE__, mach_error_string((a)));\
        return (a);\
}
#define CHECK_KRET2(a) if ((a) != KERN_SUCCESS) {return (a);}


int gettask(int pid, int* task) {
        kern_return_t kret = task_for_pid(mach_task_self(), pid, (mach_port_t*)task);
        CHECK_KRET(kret);

        return KERN_SUCCESS;
}

int getthreads(int task, void* threads, int* cnt) {
        kern_return_t kret = task_threads(task, (thread_act_port_array_t*)threads, (unsigned int*)cnt);
        CHECK_KRET(kret);

        return KERN_SUCCESS;
} 
                        

int getregs(int tid, Regs* regs) {
        mach_msg_type_number_t stateCount = x86_THREAD_STATE64_COUNT;
        kern_return_t kret = thread_get_state(tid, x86_THREAD_STATE64, (thread_state_t)regs, &stateCount);
        CHECK_KRET(kret);

        return KERN_SUCCESS;
}

int setregs(int tid, Regs* regs) {
        kern_return_t kret = thread_set_state(tid, x86_THREAD_STATE64, (thread_state_t)regs, x86_THREAD_STATE64_COUNT);
        CHECK_KRET(kret);

        return KERN_SUCCESS;
}

int vmread(int pid, ulong addr, int size, void* data, ulong* outsz) {
        int task;
        kern_return_t kret;

        kret = gettask(pid, &task);
        CHECK_KRET(kret);

        kret = vm_read_overwrite(task, addr, size, (mach_vm_address_t)data, outsz);
        CHECK_KRET(kret);

        return KERN_SUCCESS;
}

int vmwrite(int pid, ulong addr, void* data, int sz) {
        int task;
        kern_return_t kret;

        kret = gettask(pid, &task);
        CHECK_KRET(kret);

        kret = vm_write(task, addr, (mach_vm_address_t)data, sz);
        if (kret == KERN_INVALID_ADDRESS) {
                kret = vm_protect(task, addr, sz, 0, VM_PROT_WRITE|VM_PROT_READ|VM_PROT_EXECUTE);
                CHECK_KRET(kret);

                kret = vm_write(task, addr, (mach_vm_address_t)data, sz);
                CHECK_KRET(kret);
        } else {
                CHECK_KRET(kret);
        }

        return KERN_SUCCESS;
}

// Callback for exc_server below.  Called when a thread we are
// watching has an exception like hitting a breakpoint.
//kern_return_t catch_exception_raise(mach_port_t eport, mach_port_t thread,
//        mach_port_t task, exception_type_t exception,
//        exception_data_t code, mach_msg_type_number_t ncode) {
//        return onCatchExceptionRaise(eport, thread, task, exception, code, ncode);
//}

//wait for exception/signal
void server() {
        extern boolean_t exc_server(mach_msg_header_t *, mach_msg_header_t *);
        mach_msg_server(exc_server, 2048, excport, 0);
}

int threadinfo(int tid, thread_basic_info_t info) {
        unsigned int size;
        kern_return_t kret = thread_info(tid, THREAD_BASIC_INFO, (thread_info_t)info, &size);
        CHECK_KRET(kret);

        return KERN_SUCCESS;
}

int setexcport(int pid) {
        if (excport == 0) {
                extern mach_port_t mach_reply_port(void);
                excport = mach_reply_port();
                kern_return_t kret = mach_port_insert_right(mach_task_self(), excport, excport, MACH_MSG_TYPE_MAKE_SEND);
                if (kret != KERN_SUCCESS) excport = 0;
                CHECK_KRET(kret);
        }

        kern_return_t kret = task_set_exception_ports(pid, ExcMask,
                        excport, EXCEPTION_DEFAULT, MACHINE_THREAD_STATE);
        CHECK_KRET(kret);

        return KERN_SUCCESS;
}

int attach(int pid, void* ths, int* nth) {
        int task;
        kern_return_t kret = gettask(pid, &task);
        CHECK_KRET2(kret);

        getthreads(task, ths, nth);

        kret = setexcport(task);
        CHECK_KRET2(kret);
        return KERN_SUCCESS;
}

int detach(int pid) {
        //TODO
        return 0;
}

//make sure thread is resumed
int threadresume(int tid) {
        int i;
        int kret;
        struct thread_basic_info info;
        uint size = sizeof info;

        kret = thread_info(tid, THREAD_BASIC_INFO, (thread_info_t)&info, &size);
        CHECK_KRET(kret)

        for (i = 0; i < info.suspend_count; i++) {
                kret = thread_resume(tid);
                CHECK_KRET(kret);
        } 

        return KERN_SUCCESS;
}

//gcc os_darwin.c -o tfpexample -framework Security -framework CoreFoundation
//int main() {
int test() {
//        int task;
//        int kret;
//
//        byte data;
//        ulong sz;
//
//        byte cc = 0xcc;
//        int pid = 10867;
//        int tid;
//
//        pthread_t p;
//        int* thrs;
//        int nthrs;
//
//        mach_msg_type_number_t stateCount = x86_THREAD_STATE64_COUNT;
//
//        kret = getTask(pid, &task);
//        CHECK_KRET(kret);
//
//        printf("task:%d\n", task);
//
//        excport = mach_reply_port();
//        pthread_mutex_init(&mu, NULL);
//        pthread_cond_init(&cond, NULL);
//
//        pthread_create(&p, NULL, excthread, NULL);
//        kret = mach_port_insert_right(mach_task_self(), excport, excport, MACH_MSG_TYPE_MAKE_SEND);
//        CHECK_KRET(kret);
////        kret = task_set_exception_ports(task, ExcMask,
////                        excport, EXCEPTION_DEFAULT, MACHINE_THREAD_STATE);
////        CHECK_KRET(kret);
//
//
//        kret = getThreads(task, &thrs, &nthrs);
//        CHECK_KRET(kret);
//
//        printf("nthrs:%d\n", nthrs);
//
//        for (int i = 0; i < nthrs; i++) {
//                tid = thrs[i];
//                printf("tid:%d\n", tid);
//                kret = mach_port_insert_right(mach_task_self(), excport, excport, MACH_MSG_TYPE_MAKE_SEND);
//                CHECK_KRET(kret);
//
//                kret = thread_set_exception_ports(tid, ExcMask,
//                                excport, EXCEPTION_DEFAULT, MACHINE_THREAD_STATE);
//                CHECK_KRET(kret);
//
//                kret = thread_suspend(tid);
//                CHECK_KRET(kret);
//                
//                Regs regs = {0};
//                kret = getRegs(tid, &regs);
//                CHECK_KRET(kret);
//
//                char data[] = {0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc};
//                kret = writeMemory(task, regs.__rip, data, sizeof(data));
//                CHECK_KRET(kret);
//
//                kret = thread_resume(tid);
//                CHECK_KRET(kret);
//        }
//
//
//        sleep(1000000);
//
        return 0;
}

