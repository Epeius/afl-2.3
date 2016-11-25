/*
 * afl-parallel-qemu communicates with multiple qemu instance at the same time
 * to accelerate the efficiency when testing full-system software.
 */

#include "config.h"
#include "afl-parrel-qemu.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <ctype.h>
#include <fcntl.h>
#include <termios.h>
#include <dlfcn.h>
#include <assert.h>

#include <sys/wait.h>
#include <sys/time.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/file.h>

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)
#  include <sys/sysctl.h>
#endif /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */

// extern variable from afl-fuzz.c
extern u8 parallel_qemu_num;
extern QemuInstance * allQemus;
extern u32 qemu_quene_fd;
extern u8* ReadArray;
extern pid_t stuck_helper_dir;
//extern variable end
#define QEMUEXECUTABLE "/home/binzhang/EPFL/s2e-debug/qemu-debug/i386-s2e-softmmu/qemu-system-i386"
char *const qemu_argv[] ={"qemu-system-i386",
        "-m", "128",
        "-net", "none",
        "-usbdevice", "tablet",
        "-hda", "/home/binzhang/EPFL/images/debian.raw.s2e",
        "-loadvm", "forkstate",
        "-s2e-config-file", "/home/binzhang/EPFL/testfolder/forkstate.lua",
        NULL};

/*
char *const stuckhelper_argv[] ={"qemu-system-i386",
        "-m", "128",
        "-net", "none",
        "-usbdevice", "tablet",
        "-monitor", "stdio",
        "-hda", "/home/epeius/work/DSlab.EPFL/FinalTest/s2ebuild/images/debian.raw.s2e",
        "-loadvm", "forkstate_stuck_helper",
        "-s2e-config-file", "/home/epeius/work/DSlab.EPFL/FinalSubmitV2/testplace/forkstate_stuck_helper.lua",
        NULL};
*/
char QEMUEXECUTABLE1[256];
char qemu_argments[32][256];
        
/*
 * Parse qemu arguments for afl.
 */
void PARAL_QEMU(ParseQemuArgs)(char qemu_args[32][256], const char * config_filename)
{
	strcpy(qemu_args[0], "qemu-system-i386");
	FILE *config_fp;
	char StrLine[1024];
	if ((config_fp = fopen(config_filename, "r")) == NULL)
		FATAL("Cannot find qemu arguments configure file!\n");

	int index = 1;
	while (!feof(config_fp)) {
		if(!fgets(StrLine, 1024, config_fp))
			break;
		if (StrLine[0] == '#') // a comment, move onto next line
			continue;
		else{
			StrLine[strlen(StrLine)-1]='\0';
			if (strstr(StrLine, "executable:")){
				strcpy(QEMUEXECUTABLE1, StrLine+sizeof("executable"));
			} else if (strstr(StrLine, "memory:")){
				strcpy(qemu_args[index++], "-m");
				strcpy(qemu_args[index++], StrLine+sizeof("memory"));
			} else if (strstr(StrLine, "network:")){
				strcpy(qemu_args[index++], "-net");
				strcpy(qemu_args[index++], StrLine+sizeof("network"));
			} else if (strstr(StrLine, "usbdevice:")){
				strcpy(qemu_args[index++], "-usbdevice");
				strcpy(qemu_args[index++], StrLine+sizeof("usbdevice"));
			} else if (strstr(StrLine, "monitor:")){
				strcpy(qemu_args[index++], "-monitor");
				strcpy(qemu_args[index++], StrLine+sizeof("monitor"));
			} else if (strstr(StrLine, "hda:")){
				strcpy(qemu_args[index++], "-hda");
				strcpy(qemu_args[index++], StrLine+sizeof("hda"));
			} else if (strstr(StrLine, "vm:")){
				strcpy(qemu_args[index++], "-loadvm");
				strcpy(qemu_args[index++], StrLine+sizeof("vm"));
			} else if (strstr(StrLine, "configfile:")){
				strcpy(qemu_args[index++], "-s2e-config-file");
				strcpy(qemu_args[index++], StrLine+sizeof("configfile"));
			} else {
				continue;
			}
		}

	}
	fclose (config_fp);
}

/*
 * Set up share memory, which could be used for qemu to inform AFL that a test has done.
 * readyshm is handled in signal's handler.
 */
void PARAL_QEMU(SetupSHM4Ready)(void)
{
    void *shm = NULL;
    int shmid;
    shmid = shmget((key_t) READYSHMID, sizeof(u8)*65536, 0666 | IPC_CREAT);
    if (shmid == -1) {
        fprintf(stderr, "shmget failed\n");
        exit(EXIT_FAILURE);
    }
    shm = shmat(shmid, (void*) 0, 0);
    if (shm == (void*) -1)
        PFATAL("shmat() failed");
    OKF("Ready share memory attached at %X.\n", (int) shm);
    ReadArray = (u8*) shm;
}
/*
 * We don't create bitmap here because we cannot synchronize well with qemu, so give this chance to qemus.
 * While control pipes could be initialed at both sides.
 */
void PARAL_QEMU(InitQemuQueue)(void)
{
	PARAL_QEMU(ParseQemuArgs)(qemu_argments, "s2earg.config");

    system("rm -rf /tmp/afl_qemu_queue");
	int res = mkfifo(QEMUQUEUE, 0777);
	if (res != 0)
		PFATAL("mkfifo() failed");
    qemu_quene_fd = open(QEMUQUEUE, O_RDONLY|O_NONBLOCK); // we only need one queue here and set mode as read-only
    if (qemu_quene_fd == -1)
        PFATAL("Create qemu queue fifo failed.");

    if (access("/tmp/afltestcase", F_OK)) // for all testcases
        if (mkdir("/tmp/afltestcase", 0777))
            PFATAL("mkdir() failed");
    if (access("/tmp/afltracebits", F_OK)) // for all trace-bits bitmaps
        if (mkdir("/tmp/afltracebits", 0777))
            PFATAL("mkdir() failed");

    // clean test work space
    system("rm -rf /tmp/afltestcase/*");
    system("rm -rf /tmp/afltracebits/*");

    u8 i = 0;
    allQemus = (QemuInstance*) malloc(parallel_qemu_num * sizeof(QemuInstance));
    while (i < parallel_qemu_num) {
        // set up control pipe
        int fd[2];
        if (pipe(fd) != 0)
            PFATAL("pipe() failed");
        pid_t pid = fork();
        if (pid < 0)
            PFATAL("fork() failed");
        if (!pid) {
            if (dup2(fd[1], CTRLPIPE(getpid()) + 1) < 0
                                || dup2(fd[0], CTRLPIPE(getpid())) < 0) // Duplicate file descriptor before execv(), otherwise QEMU cannot access pipes forever.
                exit(EXIT_FAILURE);
            //execv(QEMUEXECUTABLE, qemu_argments);qemu_argv
            execv(QEMUEXECUTABLE, qemu_argv);
        } else {
            //TODO: remove this initial to a macro
            allQemus[i].pid = pid;
            allQemus[i].start_us = 0;
            allQemus[i].stop_us = 0;
            allQemus[i].handled = 1;
            allQemus[i].out_file = NULL;
            ReadArray[pid] = 1;
            allQemus[i].cur_queue = NULL;
            allQemus[i].cur_stage = 18; // Initial stage
            allQemus[i].cover_new = 1; // initial to play
            allQemus[i].mod_off = -1;
            u8* _tcDir = (u8*) malloc(128);
            sprintf(_tcDir, "/tmp/afltestcase/%d/", pid);
            if(access(_tcDir, F_OK))
                mkdir(_tcDir, 0777);
            allQemus[i].testcaseDir = _tcDir;
            if (dup2(fd[1], CTRLPIPE(pid) + 1) < 0
                    || dup2(fd[0], CTRLPIPE(pid)) < 0)
                PFATAL("dup2() failed");
            allQemus[i].ctrl_pipe = CTRLPIPE(pid) + 1;
            sleep(10); // why not sleep for a while.
        }
        i++;
    }
}

/*
void PARAL_QEMU(InitStuckHelper)(void)
{
    int s2e_w_fd[2]; // for s2e write
    int afl_w_fd[2]; // for afl write
    if(pipe(s2e_w_fd)!=0)
        PFATAL("pipe() for s2e failed");
    if(pipe(afl_w_fd)!=0)
        PFATAL("pipe() for afl failed");

    if (dup2(s2e_w_fd[1], S2ECTRLPIPE + 1) < 0 || dup2(s2e_w_fd[0], S2ECTRLPIPE) < 0)
        PFATAL("dup2() for s2e failed");
    if (dup2(afl_w_fd[1], AFLCTRLPIPE + 1) < 0 || dup2(afl_w_fd[0], AFLCTRLPIPE) < 0)
        PFATAL("dup2() for afl failed");
    pid_t pid = fork();
    if (pid < 0)
        PFATAL("fork() failed");
    if (!pid) {
        // start stuck helper
        execv(QEMUEXECUTABLE, stuckhelper_argv);
    } else {
        // more jobs
        OKF("[+] Starting stuck helper...");
        u8* _tcDir = (u8*) malloc(128);
        sprintf(_tcDir, "/tmp/afltestcase/%d/", pid);
        if(access(_tcDir, F_OK))
            mkdir(_tcDir, 0777);
        stuck_helper_dir = _tcDir;
        sleep(10); // why not sleep for a while.
    }
}
*/

void PARAL_QEMU(setupTracebits) (void)
{
    u8 i = 0;
    assert(allQemus);
    while (i < parallel_qemu_num) {
        key_t shmkey;
        u8* _shmfile = (u8*) malloc(128);
        if(!_shmfile)
            PFATAL("Cannot allocate memory for _shmfile");
        sprintf(_shmfile, "/tmp/afltracebits/trace_%d", allQemus[i].pid);
        printf("[+]%s\n", _shmfile);
        //hack
        while(1){
            if (!access(_shmfile, F_OK)){
                break;
            }else{
                sleep(1);
            }
        }
        if ((shmkey = ftok(_shmfile, 1)) < 0) {
            free(_shmfile);
            printf("ftok error:%s\n", strerror(errno));
            PFATAL("ftok() failed");
        }
        free(_shmfile);
        int shm_id = shmget(shmkey, MAP_SIZE, IPC_CREAT | 0600);
        if (shm_id < 0)
            PFATAL("shmget() failed");

        void * __tracebits = shmat(shm_id, NULL, 0);
        if (__tracebits == (void*) -1)
            PFATAL("shmat() failed");

        allQemus[i].trace_bits = (u8*) __tracebits;
        i++;
    }
}
