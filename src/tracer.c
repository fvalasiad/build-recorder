
/*
Copyright (C) 2022 Valasiadis Fotios
Copyright (C) 2022 Alexios Zavras
SPDX-License-Identifier: LGPL-2.1-or-later
*/

#include	"config.h"

#include	<errno.h>
#include	<stdlib.h>
#include	<stdio.h>
#include	<stddef.h>
#include	<string.h>
#include	<unistd.h>
#include	<fcntl.h>

#include	<sys/ptrace.h>

#include	<sys/signal.h>
#include	<sys/syscall.h>
#include	<sys/wait.h>

#ifdef BUILDING_ON_LINUX
#include	<linux/ptrace.h>
#include	<linux/limits.h>
#endif

#ifdef BUILDING_ON_FREEBSD
#include	<sys/sysctl.h>
#include	<sys/types.h>
#include	<sys/user.h>
#endif

#include	"types.h"
#include	"hash.h"
#include	"record.h"

/*
 * variables for the list of processes,
 * its size and the array size. As well as
 * a list of their respective pids with the
 * same size and array size.
 */

#ifdef BUILDING_ON_FREEBSD
lwpid_t *fbsdpids;
#endif
pid_t *pids;
PROCESS_INFO *pinfo;
int numpinfo;
int pinfo_size;

FILE_INFO *finfo;
int numfinfo;
int finfo_size;

#define	DEFAULT_PINFO_SIZE	32
#define	DEFAULT_FINFO_SIZE	32

/*
 * memory allocators for pinfo
 */

void
init(void)
{
    pinfo_size = DEFAULT_PINFO_SIZE;
    pinfo = calloc(pinfo_size, sizeof (PROCESS_INFO));
    if (!pinfo) {
	perror("tracer.c:init():calloc(pinfo)");
	exit(EXIT_FAILURE);
    }
    pids = malloc(pinfo_size * sizeof (pid_t));
    if (!pids) {
	perror("tracer.c:init():malloc(pids)");
	exit(EXIT_FAILURE);
    }
#ifdef BUILDING_ON_FREEBSD
    fbsdpids = malloc(pinfo_size * sizeof (lwpid_t));
    if (!fbsdpids) {
	perror("tracer.c:init():malloc(fbsdpids)");
	exit(EXIT_FAILURE);
    }
#endif
    numpinfo = -1;

    finfo_size = DEFAULT_FINFO_SIZE;
    finfo = calloc(finfo_size, sizeof (FILE_INFO));
    if (!finfo) {
	perror("tracer.c:init():malloc(finfo)");
	exit(EXIT_FAILURE);
    }

    numfinfo = -1;
}

PROCESS_INFO *
next_pinfo(pid_t pid)
{
    if (numpinfo == pinfo_size - 1) {
	pinfo_size *= 2;
	pinfo = reallocarray(pinfo, pinfo_size, sizeof (PROCESS_INFO));
	if (pinfo == NULL) {
	    perror("tracer.c:next_pinfo:reallocarray(pinfo)");
	    exit(EXIT_FAILURE);
	}

	pids = reallocarray(pids, pinfo_size, sizeof (pid_t));
	if (pids == NULL) {
	    perror("tracer.c:next_pinfo:reallocarray(pids)");
	    exit(EXIT_FAILURE);
	}

#ifdef BUILDING_ON_FREEBSD
	fbsdpids = reallocarray(fbsdpids, pinfo_size, sizeof (lwpid_t));
	if (fbsdpids == NULL) {
	    perror("tracer.c:next_pinfo:reallocarray(fbsdpids)");
	    exit(EXIT_FAILURE);
	}
#endif
    }

    pids[numpinfo + 1] = pid;
    return pinfo + (++numpinfo);
}

FILE_INFO *
next_finfo(void)
{
    if (numfinfo == finfo_size - 1) {
	finfo_size *= 2;
	finfo = reallocarray(finfo, finfo_size, sizeof (FILE_INFO));
	if (finfo == NULL) {
	    perror("tracer.c:next_finfo:reallocarray(finfo)");
	    exit(EXIT_FAILURE);
	}
    }

    return finfo + (++numfinfo);
}

void
pinfo_new(PROCESS_INFO *self, char ignore_one_sigstop)
{
    static int pcount = 0;

    sprintf(self->outname, ":p%d", pcount++);
    self->finfo_size = DEFAULT_FINFO_SIZE;
    self->numfinfo = -1;
    self->finfo = malloc(self->finfo_size * sizeof (FILE_INFO));
    self->fds = malloc(self->finfo_size * sizeof (int));
    self->ignore_one_sigstop = ignore_one_sigstop;
}

void
finfo_new(FILE_INFO *self, char *path, char *abspath, char *hash, size_t sz)
{
    static int fcount = 0;

    self->path = path;
    self->abspath = abspath;
    self->hash = hash;
    self->size = sz;
    sprintf(self->outname, ":f%d", fcount++);
}

PROCESS_INFO *
find_pinfo(pid_t pid)
{
    int i = numpinfo;

    while (i >= 0 && pids[i] != pid) {
	--i;
    }

    if (i < 0) {
	return NULL;
    }

    return pinfo + i;
}

FILE_INFO *
find_finfo(char *abspath, char *hash)
{
    int i = numfinfo;

    while (i >= 0) {
	if (!strcmp(abspath, finfo[i].abspath)
	    && ((hash == NULL && finfo[i].hash == NULL)
		|| (hash != NULL && finfo[i].hash != NULL
		    && !strcmp(hash, finfo[i].hash)))) {

	    break;
	}

	--i;
    }

    if (i < 0) {
	return NULL;
    }

    return finfo + i;
}

FILE_INFO *
pinfo_find_finfo(PROCESS_INFO *self, int fd)
{
    int i = self->numfinfo;

    while (i >= 0 && self->fds[i] != fd) {
	--i;
    }

    if (i < 0) {
	return NULL;
    }

    return self->finfo + i;
}

FILE_INFO *
pinfo_next_finfo(PROCESS_INFO *self, int fd)
{
    if (self->numfinfo == self->finfo_size - 1) {
	self->finfo_size *= 2;
	self->finfo =
		reallocarray(self->finfo, self->finfo_size, sizeof (FILE_INFO));
	self->fds =
		reallocarray(self->fds, self->finfo_size, sizeof (FILE_INFO));
	if (self->finfo == NULL) {
	    perror("tracer.c:pinfo_next_finfo:reallocarray(pinfo->finfo)");
	    exit(EXIT_FAILURE);
	}
    }

    self->fds[self->numfinfo + 1] = fd;
    return self->finfo + (++self->numfinfo);
}

char *
get_str_from_process(pid_t pid, void *addr)
{
    static char buf[PATH_MAX];
    char *dest = buf;
#ifdef BUILDING_ON_LINUX
    union {
	long ival;
	char cval[sizeof (long)];
    } data;
#else // FreeBSD
    union {
	int ival;
	char cval[sizeof (int)];
    } data;
#endif

    size_t i = 0;

    do {
	data.ival =
#ifdef BUILDING_ON_LINUX
		ptrace(PTRACE_PEEKDATA, pid, (char *) addr + i * sizeof (data.ival),
		       NULL);
#else // FreeBSD
		ptrace(PT_READ_D, pid, (char *) addr + i * sizeof(data.ival), 0);
#endif
	for (unsigned j = 0; j < sizeof (data.ival); j++) {
	    *dest++ = data.cval[j];
	    if (data.cval[j] == 0)
		break;
	}
	++i;
    } while (dest[-1]);

    char *ret = strdup(buf);
    if (!ret) {
	perror("tracer.c:get_str_from_process():strdup(buf)");
	exit(EXIT_FAILURE);
    }
    return ret;
}

char *
absolutepath(pid_t pid, int dirfd, char *addr)
{
    char symbpath[PATH_MAX];

    if (*addr == '/') {
	return realpath(addr, NULL);
    }
    if (dirfd == AT_FDCWD) {
#ifdef BUILDING_ON_LINUX
	int bytes = snprintf(symbpath, PATH_MAX, "/proc/%d/cwd/%s", pid, addr);
	if (bytes >= PATH_MAX) {
	    perror("tracer.c:absolutepath():snprintf(/proc/%d/cwd/%s): truncating string");
	    exit(EXIT_FAILURE);
	}
#else
	int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_CWD, pid};
	size_t len;
	struct kinfo_file *kif;

	if (sysctl(mib, sizeof(mib) / sizeof(int), NULL, &len, NULL, 0) < 0) {
	    perror("sysctl");
	    exit(EXIT_FAILURE);
	}

	kif = malloc(len);
	if (!kif) {
	    perror("sysctl");
	}

	if (sysctl(mib, sizeof(mib) / sizeof(int), kif, &len, NULL, 0) < 0) {
	    perror("sysctl");
	    exit(EXIT_FAILURE);
	}

	int bytes = snprintf(symbpath, PATH_MAX, "%s/%s", kif->kf_path, addr);
	if (bytes >= PATH_MAX) {
	    perror("tracer.c:absolutepath():snprintf(%s/%s): truncating string");
	    exit(EXIT_FAILURE);
	}
	free(kif);
#endif
	return realpath(symbpath, NULL);
    }

#ifdef BUILDING_ON_LINUX
    int bytes = snprintf(symbpath, PATH_MAX, "/proc/%d/fd/%d/%s", pid, dirfd, addr);
    if (bytes >= PATH_MAX) {
	perror("tracer.c:absolutepath():snprintf(/proc/%d/fd/%d/%s): truncating string");
	exit(EXIT_FAILURE);
    }
#else
    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_FILEDESC, pid};
    size_t len;
    struct kinfo_file *kif;
    
    if (sysctl(mib, sizeof(mib) / sizeof(int), NULL, &len, NULL, 0) < 0) {
	perror("sysctl");
	exit(EXIT_FAILURE);
    }

    kif = malloc(len);
    if (!kif) {
	perror("sysctl");
    }

    if (sysctl(mib, sizeof(mib) / sizeof(int), kif, &len, NULL, 0) < 0) {
	perror("sysctl");
	exit(EXIT_FAILURE);
    }

    size_t count = len / sizeof(struct kinfo_file);
    size_t i;
    for (i = 0; i < count; i++) {
        if (kif[i].kf_fd == dirfd /*&& kif[i].kf_type == KF_TYPE_VNODE*/) {  
            //printf("FD: %d, Path: %s\n", kif[i].kf_fd, kif[i].kf_path);
	    break;
        }
    }

    if (i == count) {
	free(kif);
	errno = ENOENT; // Replicating the Linux behavior.
	return NULL;
    }

    int bytes = snprintf(symbpath, PATH_MAX, "%s/%s", kif[i].kf_path, addr);
    if (bytes >= PATH_MAX) {
	perror("tracer.c:absolutepath():snprintf(%s/%s, kf_path): truncating string");
	exit(EXIT_FAILURE);
    }
    free(kif);
#endif
    return realpath(symbpath, NULL);
}

char *
find_in_path(char *path)
{
    static char buf[PATH_MAX];
    char *ret;
    char *PATH = strdup(getenv("PATH"));

    if (!PATH) {
	perror("tracer.c:find_in_path():strdup(getenv(PATH))");
	exit(EXIT_FAILURE);
    }
    char *it = PATH;
    char *last;

    do {
	last = strchr(it, ':');
	if (last) {
	    *last = '\0';
	}

	sprintf(buf, "%s/%s", it, path);
	ret = realpath(buf, NULL);
	if (!ret && (errno != 0 && errno != ENOENT)) {
	    fprintf(stderr, "tracer.c:find_in_path:realpath(%s): %s\n", path,
		    strerror(errno));
	    exit(EXIT_FAILURE);
	}
	it = last + 1;
    } while (last != NULL && ret == NULL);

    free(PATH);

    return ret;
}

static size_t
get_file_size(char *fname)
{
    struct stat fstat;

    if (stat(fname, &fstat)) {
	fprintf(stderr, "tracer.c:get_file_size(%s): %s\n", fname,
		strerror(errno));
	return -1;
    }

    return fstat.st_size;
}

static void
handle_open(pid_t pid, PROCESS_INFO *pi, int fd, int dirfd, void *path,
	    int purpose)
{
    path = get_str_from_process(pid, path);
    char *abspath = absolutepath(pid, dirfd, path);

    if (abspath == NULL) {
	fprintf(stderr, "tracer.c:handle_open:absolutepath(%s): %s\n",
		(char *) path, strerror(errno));
	exit(EXIT_FAILURE);
    }

    FILE_INFO *f = NULL;

    if ((purpose & O_ACCMODE) == O_RDONLY) {
	char *hash = get_file_hash(abspath);
	size_t sz = get_file_size(abspath);

	f = find_finfo(abspath, hash);
	if (!f) {
	    f = next_finfo();
	    finfo_new(f, path, abspath, hash, sz);
	    record_file(f->outname, path, abspath);
	    record_hash(f->outname, hash);
	    record_size(f->outname, sz);
	} else {
	    free(path);
	    free(abspath);
	    free(hash);
	}
    } else {
	f = pinfo_next_finfo(pi, fd);
	finfo_new(f, path, abspath, NULL, -1);
	record_file(f->outname, path, abspath);
    }

    record_fileuse(pi->outname, f->outname, purpose);
}

static void
handle_execve(pid_t pid, PROCESS_INFO *pi, int dirfd, char *path)
{
    record_process_start(pid, pi->outname);

    char *abspath = absolutepath(pid, dirfd, path);

    if (!abspath) {
	if (errno != ENOENT) {
	    fprintf(stderr, "tracer.c:handle_execve:absolutepath(%s): %s\n",
		    path, strerror(errno));
	    exit(EXIT_FAILURE);
	}

	abspath = find_in_path(path);

	if (!abspath) {
	    fprintf(stderr, "tracer.c:handle_execve:find_in_path(%s): %s\n",
		    path, strerror(errno));
	    exit(EXIT_FAILURE);
	}
    }

    char *hash = get_file_hash(abspath);
    size_t sz = get_file_size(abspath);

    FILE_INFO *f;

    if (!(f = find_finfo(abspath, hash))) {
	f = next_finfo();

	finfo_new(f, path, abspath, hash, sz);
	record_file(f->outname, path, abspath);
	record_hash(f->outname, f->hash);
	record_size(f->outname, sz);
    } else {
	free(abspath);
	free(hash);
	free(path);
    }

    record_exec(pi->outname, f->outname);
}

static void
handle_rename_entry(pid_t pid, PROCESS_INFO *pi, int olddirfd, char *oldpath)
{
    pi->entry_info = absolutepath(pid, olddirfd, oldpath);
    free(oldpath);
}

static void
handle_rename_exit(pid_t pid, PROCESS_INFO *pi, char *oldpath, int newdirfd,
		   char *newpath)
{
    char *oldabspath = pi->entry_info;
    char *newabspath = absolutepath(pid, newdirfd, newpath);
    size_t sz = get_file_size(newabspath);

    char *hash = get_file_hash(newabspath);

    FILE_INFO *from = find_finfo(oldabspath, hash);

    if (!from) {
	from = next_finfo();
	finfo_new(from, oldpath, oldabspath, hash, sz);
	record_file(from->outname, oldpath, oldabspath);
	record_hash(from->outname, hash);
	record_size(from->outname, sz);
    } else {
	free(oldpath);
	free(oldabspath);
    }

    FILE_INFO *to = find_finfo(newabspath, hash);

    if (!to) {
	to = next_finfo();
	finfo_new(to, newpath, newabspath, hash, sz);
	record_file(to->outname, newpath, newabspath);
	record_hash(to->outname, hash);
	record_size(to->outname, sz);
    } else {
	free(newpath);
	free(newabspath);
	if (from->hash != hash) {
	    free(hash);
	}
    }

    record_rename(pi->outname, from->outname, to->outname);
}

static void
handle_syscall_entry(pid_t pid, PROCESS_INFO *pi)
		     
{
    int olddirfd;
    char *oldpath;

    switch (pi->nr) {
#ifdef HAVE_SYS_RENAME
	case SYS_rename:
	    // int rename(const char *oldpath, const char *newpath);
	    oldpath = get_str_from_process(pid, (void *) pi->args[0]);
	    handle_rename_entry(pid, pi, AT_FDCWD, oldpath);
	    break;
#endif
#ifdef HAVE_SYS_RENAMEAT
	case SYS_renameat:
	    // int renameat(int olddirfd, const char *oldpath, int newdirfd,
	    // const char *newpath);
	    olddirfd = pi->args[0];
	    oldpath = get_str_from_process(pid, (void *) pi->args[1]);
	    handle_rename_entry(pid, pi, olddirfd, oldpath);
	    break;
#endif
#ifdef HAVE_SYS_RENAMEAT2
	case SYS_renameat2:
	    // int renameat2(int olddirfd, const char *oldpath, int newdirfd,
	    // const char *newpath, unsigned int flags);
	    olddirfd = pi->args[0];
	    oldpath = get_str_from_process(pid, (void *) pi->args[1]);
	    handle_rename_entry(pid, pi, olddirfd, oldpath);
	    break;
#endif
#ifdef HAVE_SYS_EXECVE
	case SYS_execve:
	    pi->entry_info = get_str_from_process(pid, (void *) pi->args[0]);
	    break;
#endif
#ifdef HAVE_SYS_EXECVEAT
	case SYS_execveat:
	    pi->entry_info = get_str_from_process(pid, (void *) pi->args[1]);
	    break;
#endif
    }
}

static void
handle_syscall_exit(pid_t pid, PROCESS_INFO *pi, int64_t rval)
{
    if (rval < 0) {
	return;			       // return on syscall failure
    }

    int fd;
    void *path;
    int flags;
    int dirfd;
    FILE_INFO *f;
    char *oldpath;
    int newdirfd;
    char *newpath;

    switch (pi->nr) {
#ifdef HAVE_SYS_OPEN
	case SYS_open:
	    // int open(const char *pathname, int flags, ...);
	    fd = (int) rval;
	    path = (void *) pi->args[0];
	    flags = (int) pi->args[1];

	    handle_open(pid, pi, fd, AT_FDCWD, path, flags);
	    break;
#endif
#ifdef HAVE_SYS_CREAT
	case SYS_creat:
	    // int creat(const char *pathname, ...);
	    fd = (int) rval;
	    path = (void *) pi->args[0];

	    handle_open(pid, pi, fd, AT_FDCWD, path,
			O_CREAT | O_WRONLY | O_TRUNC);
	    break;
#endif
#ifdef HAVE_SYS_OPENAT
	case SYS_openat:
	    // int openat(int dirfd, const char *pathname, int flags, ...);
	    fd = (int) rval;
	    dirfd = (int) pi->args[0];
	    path = (void *) pi->args[1];
	    flags = (int) pi->args[2];

	    handle_open(pid, pi, fd, dirfd, path, flags);
	    break;
#endif
#ifdef HAVE_SYS_CLOSE
	case SYS_close:
	    // int close(int fd);
	    fd = (int) pi->args[0];

	    f = pinfo_find_finfo(pi, fd);

	    if (f != NULL) {
		f->hash = get_file_hash(f->abspath);
		f->size = get_file_size(f->abspath);

		record_hash(f->outname, f->hash);
		record_size(f->outname, f->size);

		// Add it to global cache list
		*next_finfo() = *f;

		// Remove the file from the process' list
		for (int i = f - pi->finfo; i < pi->numfinfo; ++i) {
		    pi->finfo[i] = pi->finfo[i + 1];
		}

		for (int i = f - pi->finfo; i < pi->numfinfo; ++i) {
		    pi->fds[i] = pi->fds[i + 1];
		}

		--pi->numfinfo;
	    }
	    break;
#endif
#ifdef HAVE_SYS_EXECVE
	case SYS_execve:
	    // int execve(const char *pathname, char *const argv[],
	    // char *const envp[]);
	    path = pi->entry_info;

	    handle_execve(pid, pi, AT_FDCWD, path);
	    break;
#endif
#ifdef HAVE_SYS_EXECVEAT
	case SYS_execveat:
	    // int execveat(int dirfd, const char *pathname,
	    // const char *const argv[], const char * const envp[],
	    // int flags);
	    dirfd = pi->args[0];
	    path = pi->entry_info;

	    handle_execve(pid, pi, dirfd, path);
	    break;
#endif
#ifdef HAVE_SYS_RENAME
	case SYS_rename:
	    // int rename(const char *oldpath, const char *newpath);
	    oldpath = get_str_from_process(pid, (void *) pi->args[0]);
	    newpath = get_str_from_process(pid, (void *) pi->args[1]);

	    handle_rename_exit(pid, pi, oldpath, AT_FDCWD, newpath);
	    break;
#endif
#ifdef HAVE_SYS_RENAMEAT
	case SYS_renameat:
	    // int renameat(int olddirfd, const char *oldpath, int newdirfd,
	    // const char *newpath);
	    oldpath = get_str_from_process(pid, (void *) pi->args[1]);
	    newdirfd = pi->args[2];
	    newpath = get_str_from_process(pid, (void *) pi->args[3]);

	    handle_rename_exit(pid, pi, oldpath, newdirfd, newpath);
	    break;
#endif
#ifdef HAVE_SYS_RENAMEAT2
	case SYS_renameat2:
	    // int renameat2(int olddirfd, const char *oldpath, int newdirfd,
	    // const char *newpath, unsigned int flags);
	    oldpath = get_str_from_process(pid, (void *) pi->args[1]);
	    newdirfd = pi->args[2];
	    newpath = get_str_from_process(pid, (void *) pi->args[3]);

	    handle_rename_exit(pid, pi, oldpath, newdirfd, newpath);
	    break;
#endif
    }
}

#ifdef BUILDING_ON_LINUX
static void
tracer_main(pid_t pid, char *path, char **envp)
{
    waitpid(pid, NULL, 0);

    PROCESS_INFO *pi = next_pinfo(pid);
    pinfo_new(pi, 0);

    record_process_env(pi->outname, envp);
    handle_execve(pid, pi, AT_FDCWD, path);

    ptrace(PTRACE_SETOPTIONS, pid, NULL,	// Options are inherited
	   PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE |
	   PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK);

    struct ptrace_syscall_info info;
    static size_t running = 1;

    int status;
    PROCESS_INFO *process_state;

    // Starting tracee
    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) {
	perror("tracer.c:tracer_main():ptrace(tracee PTRACE_SYSCALL)");
	exit(EXIT_FAILURE);
    }

    while (running) {
	pid = wait(&status);

	if (pid < 0) {
	    perror("tracer.c:tracer_main():wait()");
	    exit(EXIT_FAILURE);
	}

	unsigned int restart_sig = 0;

	if (WIFSTOPPED(status)) {
	    switch (WSTOPSIG(status)) {
		case SIGTRAP | 0x80:
		    process_state = find_pinfo(pid);
		    if (!process_state) {
			fprintf(stderr,
				"tracer.c:tracer_main():find_pinfo() on syscall sigtrap\n");
			exit(EXIT_FAILURE);
		    }

		    if (ptrace
			(PTRACE_GET_SYSCALL_INFO, pid, (void *) sizeof (info),
			 &info) < 0) {
			perror("tracer.c:tracer_main():ptrace(PTRACE_GET_SYSCALL_INFO)");
			exit(EXIT_FAILURE);
		    }

		    switch (info.op) {
			case PTRACE_SYSCALL_INFO_ENTRY:
			    process_state->nr = info.entry.nr;
			    memcpy(process_state->args, info.entry.args,
				   6 * sizeof (uint64_t));
			    handle_syscall_entry(pid, process_state);
			    break;
			case PTRACE_SYSCALL_INFO_EXIT:
			    handle_syscall_exit(pid, process_state,
						info.exit.rval);
			    break;
			default:
			    fprintf(stderr,
				    "tracer.c:tracer_main():WSTOPSIG(%d) expected PTRACE_SYSCALL_INFO_ENTRY or PTRACE_SYSCALL_INFOO_EXIT: %s\n",
				    WSTOPSIG(status), strerror(errno));
			    exit(EXIT_FAILURE);
		    }

		    break;
		case SIGSTOP:
		    // We only want to ignore post-attach SIGSTOP, for the
		    // rest we shouldn't mess with.
		    if ((process_state = find_pinfo(pid))) {
			if (process_state->ignore_one_sigstop == 0) {
			    restart_sig = WSTOPSIG(status);
			} else {
			    ++running;
			    process_state->ignore_one_sigstop = 0;
			}
		    } else {
			++running;
			PROCESS_INFO *pi = next_pinfo(pid);

			pinfo_new(pi, 0);
		    }
		    break;
		case SIGTRAP:
		    // Also ignore SIGTRAPs since they are
		    // generated by ptrace(2)
		    switch (status >> 8) {
			case SIGTRAP | (PTRACE_EVENT_VFORK << 8):
			case SIGTRAP | (PTRACE_EVENT_FORK << 8):
			case SIGTRAP | (PTRACE_EVENT_CLONE << 8):
			    pid_t child;

			    if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &child) <
				0) {
				perror("tracer.c:tracer_main():ptrace(PTRACE_GETEVENTMSG)");
				exit(EXIT_FAILURE);
			    }

			    PROCESS_INFO *child_pi = find_pinfo(child);

			    if (!child_pi) {
				child_pi = next_pinfo(child);
				pinfo_new(child_pi, 1);
			    }
			    record_process_create(pi->outname,
						  child_pi->outname);
		    }
		    break;
		default:
		    restart_sig = WSTOPSIG(status);
	    }

	    // Restarting process 
	    if (ptrace(PTRACE_SYSCALL, pid, NULL, restart_sig) < 0) {
		perror("tracer.c:tracer_main():ptrace(): failed restarting process");
		exit(EXIT_FAILURE);
	    }
	} else if (WIFEXITED(status)) {	// child process exited 
	    --running;

	    process_state = find_pinfo(pid);
	    if (!process_state) {
		fprintf(stderr,
			"tracer.c:tracer_main():find_pinfo on WIFEXITED\n");
		exit(EXIT_FAILURE);
	    }

	    record_process_end(process_state->outname);

	    free(process_state->cmd_line);
	    free(process_state->finfo);
	    free(process_state->fds);

	    for (int i = process_state - pinfo; i < numpinfo; ++i) {
		pinfo[i] = pinfo[i + 1];
	    }
	    for (int i = process_state - pinfo; i < numpinfo; ++i) {
		pids[i] = pids[i + 1];
	    }
	    --numpinfo;
	}
    }
}
#endif

#ifdef BUILDING_ON_FREEBSD
static void
tracer_main(pid_t pid, char *path, char **envp)
{
    pid = waitpid(pid, NULL, 0);

    struct ptrace_lwpinfo lwpinfo;
    if (ptrace(PT_LWPINFO, pid, (caddr_t) &lwpinfo, sizeof(lwpinfo)) < 0) {
	perror("tracer.c:tracer_main:ptrace(PT_LWPINFO)");
	exit(EXIT_FAILURE);
    }
    int lwpid = lwpinfo.pl_lwpid;

    PROCESS_INFO *pi = next_pinfo(lwpid);
    pinfo_new(pi, 0);
    fbsdpids[pi - pinfo] = pid;

    record_process_env(pi->outname, envp);
    handle_execve(lwpid, pi, AT_FDCWD, path);

    int event_mask = PTRACE_SYSCALL | PTRACE_FORK | PTRACE_LWP | PTRACE_VFORK;
    if (ptrace(PT_SET_EVENT_MASK, lwpid, (caddr_t) &event_mask, sizeof(event_mask)) < 0) {
	perror("tracer.c:tracer_main():ptrace(initial PT_SET_EVENT_MASK)");
	exit(EXIT_FAILURE);
    }

    int status;
    PROCESS_INFO *process_state;

    // Starting tracee
    if (ptrace(PT_CONTINUE, lwpid, (caddr_t) 1, 0) < 0) {
	perror("tracer.c:tracer_main():ptrace(tracee PT_CONTINUE)");
	exit(EXIT_FAILURE);
    }

    while (numpinfo >= 0) {
	pid = wait(&status);

	if (pid < 0) {
	    perror("tracer.c:tracer_main():wait()");
	    exit(EXIT_FAILURE);
	}

	if (WIFSTOPPED(status)) {
	    int sig = WSTOPSIG(status);

	    if (ptrace(PT_LWPINFO, pid, (caddr_t) &lwpinfo, sizeof(lwpinfo)) < 0) {
		perror("tracer.c:tracer_main:ptrace(PT_LWPINFO)");
		exit(EXIT_FAILURE);
	    }
	    lwpid = lwpinfo.pl_lwpid;

	    if ((sig != SIGSTOP || !(lwpinfo.pl_flags & PL_FLAG_BORN)) && sig != SIGTRAP) {
		if (ptrace(PT_CONTINUE, lwpid, (caddr_t)1, sig) < 0) {
		    perror("tracer.c:tracer_main:ptrace(PT_CONTINUE)");
		}
		continue;
	    }

	    process_state = find_pinfo(lwpid);
	    if (!process_state) {
		process_state = next_pinfo(lwpid);
		pinfo_new(process_state, 0);
		fbsdpids[process_state - pinfo] = pid;
	    }

	    int flags = lwpinfo.pl_flags;
	    if (flags & PL_FLAG_SCE) {
		process_state->nr = lwpinfo.pl_syscall_code;
		if (ptrace(PT_GET_SC_ARGS, lwpid, (caddr_t) process_state->args, lwpinfo.pl_syscall_narg * sizeof (uint64_t)) < 0) {
		    perror("trace.c:tracer_main:ptrace(PT_GET_SC_ARGS)");
		    exit(EXIT_FAILURE);
		}

		handle_syscall_entry(lwpid, process_state);
	    } else if (flags & PL_FLAG_SCX) {
		struct ptrace_sc_ret ret;
		if (ptrace(PT_GET_SC_RET, lwpid, (caddr_t) &ret, sizeof(ret)) < 0) {
		    perror("trace.c:tracer_main:ptrace(PT_GET_SC_RET)");
		    exit(EXIT_FAILURE);
		}

		handle_syscall_exit(lwpid, process_state, !ret.sr_error ? ret.sr_retval[0] : -1);
	    } else if (flags & PL_FLAG_CHILD) {
		ptrace(PT_SET_EVENT_MASK, lwpid, (caddr_t) &event_mask, sizeof(event_mask));	
	    } else if (flags & PL_FLAG_EXITED) {
		record_process_end(process_state->outname);

		free(process_state->cmd_line);
		free(process_state->finfo);
		free(process_state->fds);

		--numpinfo;
		for (int i = process_state  - pinfo; i < numpinfo; ++i) {
		    pinfo[i] = pinfo[i + 1];
		}
		for (int i = process_state - pinfo; i < numpinfo; ++i) {
		    pids[i] = pids[i + 1];
		}
		for (int i = process_state - pinfo; i < numpinfo; ++i) {
		    fbsdpids[i] = fbsdpids[i + 1];
		}
	    }

	    // Restarting process 
	    if (ptrace(PT_CONTINUE, lwpid, (caddr_t) 1, 0) < 0) {
		perror("tracer.c:tracer_main():ptrace(PT_CONTINUE): failed restarting process");
		exit(EXIT_FAILURE);
	    }
	} else if (WIFEXITED(status)) {	// child process exited 
	    int i = numpinfo;

	    while (i >= 0 && fbsdpids[i] != pid) {
		--i;
	    }

	    if (i < 0) {
		perror("tracer.c:tracer_main():find_fbsdpids(): failure to find last LWP");
		exit(EXIT_FAILURE);
	    }

	    process_state = pinfo + i;

	    record_process_end(process_state->outname);

	    free(process_state->cmd_line);
	    free(process_state->finfo);
	    free(process_state->fds);

	    --numpinfo;
	    for (int i = process_state  - pinfo; i < numpinfo; ++i) {
		pinfo[i] = pinfo[i + 1];
	    }
	    for (int i = process_state - pinfo; i < numpinfo; ++i) {
		pids[i] = pids[i + 1];
	    }
	    for (int i = process_state - pinfo; i < numpinfo; ++i) {
		fbsdpids[i] = fbsdpids[i + 1];
	    }
	}
    }
}
#endif

void
run_tracee(char **av)
{
#ifdef BUILDING_ON_LINUX
    ptrace(PTRACE_TRACEME, NULL, NULL, NULL);
#else
    ptrace(PT_TRACE_ME, 0, NULL, 0);
#endif
    execvp(*av, av);
    perror("tracer.c:run_tracee():execvp(): after child exec()");
    exit(EXIT_FAILURE);
}

void
run_and_record_fnames(char **av, char **envp)
{
    pid_t pid;

    pid = fork();
    if (pid < 0) {
	perror("tracer.c:run_and_record_fnames(): in original fork()");
	exit(EXIT_FAILURE);
    } else if (pid == 0)
	run_tracee(av);

    init();
    tracer_main(pid, *av, envp);
}
