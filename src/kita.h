#ifndef LIBKITA_H
#define LIBKITA_H

#include <stdio.h>  // _IONBF, _IOLBF, _IOFBF
#include <unistd.h> // STDOUT_FILENO, STDIN_FILENO, STDERR_FILENO

// Program information
#define KITA_NAME      "libkita"
#define KITA_URL       "https://github.com/domsson/libkita"
#define KITA_VER_MAJOR  0
#define KITA_VER_MINOR  1
#define KITA_VER_PATCH  0

// Buffers etc
#define KITA_BUFFER_SIZE 2048
#define KITA_MS_PER_S 1000

// Errors
#define KITA_ERR_NONE            0
#define KITA_ERR_OTHER          -1
#define KITA_ERR_EPOLL_CREATE   -8
#define KITA_ERR_EPOLL_CTL      -9
#define KITA_ERR_EPOLL_WAIT    -10 // epoll_pwait() error
#define KITA_ERR_EPOLL_SIG     -11 // epoll_pwait() caught a signal

/*
 * Enums
 */

enum kita_ios_type {
	KITA_IOS_IN  = STDIN_FILENO,  // 0
	KITA_IOS_OUT = STDOUT_FILENO, // 1
	KITA_IOS_ERR = STDERR_FILENO  // 2
};

enum kita_buf_type {
	KITA_BUF_NONE = _IONBF,  // 0x0004
	KITA_BUF_LINE = _IOLBF,  // 0x0040
	KITA_BUF_FULL = _IOFBF   // 0x0000
};

typedef enum kita_ios_type kita_ios_type_e;
typedef enum kita_buf_type kita_buf_type_e;

/*
 * Structs 
 */

struct kita_state;
struct kita_child;
struct kita_event;
struct kita_calls;
struct kita_stream;

typedef struct kita_state kita_state_s;
typedef struct kita_child kita_child_s;
typedef struct kita_event kita_event_s;
typedef struct kita_calls kita_calls_s;
typedef struct kita_stream kita_stream_s;

typedef void (*kita_call)(kita_state_s *s, kita_event_s *e);

struct kita_calls
{
	// TODO let's rethink these names...
	kita_call child_born;
	kita_call child_died;
	kita_call child_reap;
	kita_call child_stdin_data;
	kita_call child_stdout_data;
	kita_call child_stderr_data;
	kita_call child_stdin_died;
	kita_call child_stdout_died;
	kita_call child_stderr_died;
	// TODO what else?
};

struct kita_stream
{
	FILE *fp;

	kita_ios_type_e ios_type;
	kita_buf_type_e buf_type;
	unsigned blocking : 1;

	unsigned ready : 1;    // ready to read or write data?
	double last;           // time of last read or write
};

struct kita_child
{
	char *cmd;             // command/binary to run (could have arguments)
	char *arg;             // additional argument string (optional)
	pid_t pid;             // process ID

	kita_stream_s *io[3];

	void *ctx;
};

struct kita_event
{
	kita_child_s *child;     // pointer to the child process struct 
	kita_ios_type_e ios;     // stdin, stdout, stderr?
	int fd;                  // file descriptor for the relevant child's stream
};

struct kita_state
{
	kita_child_s *children; // child processes
	size_t num_children;    // num of child processes

	kita_calls_s cbs;      // event callbacks

	int epfd;              // epoll file descriptor
	int error;             // last error that occured

	void *ctx;             // user data ('context')
};

/*
 * Public functions 
 */

// Initialization
kita_state_s *kita_init();
kita_calls_s *kita_get_callbacks(kita_state_s *s);

// Main flow control
int kita_loop(kita_state_s *s);
int kita_tick(kita_state_s *s, int timeout);

// Children: creating, deleting and manipulating
kita_child_s *kita_child_init(kita_child_s *s, int in, int out, int err);
kita_child_s *kita_child_add(kita_state_s *s, kita_child_s *c);
int           kita_child_del(kita_state_s *s, kita_child_s *c);
int           kita_child_reg_ev(kita_state_s *, kita_child_s *c);
int           kita_child_rem_ev(kita_state_s *, kita_child_s *c);
int           kita_child_has_io(kita_child_s *c, kita_ios_type_e n);
FILE         *kita_child_get_fp(kita_child_s *c, kita_ios_type_e n);
int           kita_child_get_fd(kita_child_s *c, kita_ios_type_e n);
int           kita_child_set_blocking(kita_child_s *c, kita_ios_type_e n, int blocking);
int           kita_child_get_blocking(kita_child_s *c, kita_ios_type_e n);
int           kita_child_set_buf_type(kita_child_s *c, kita_ios_type_e n, kita_buf_type_e b);
void          kita_child_set_context(kita_child_s *c, void *ctx);
void         *kita_child_get_context(kita_child_s *c);

// Children: find, retrieve
kita_child_s *kita_child_find_by_cmd(kita_state_s *s, const char *cmd);
kita_child_s *kita_child_find_by_pid(kita_state_s *s, pid_t pid);

// Children: opening, reading, writing, killing
int   kita_child_open(kita_child_s *child);
char *kita_child_read(kita_child_s *child, kita_ios_type_e n, char *buf, size_t len);
int   kita_child_feed(kita_child_s *child, const char *str);
int   kita_child_kill(kita_child_s *child);
int   kita_child_term(kita_child_s *child);

// Children: inquire, status
int kita_child_is_open(kita_child_s *child);

// Clean-up and shut-down
void kita_kill(kita_state_s *s);
void kita_free(kita_state_s *s);

// Retrieval of data from the twirc state
int kita_get_last_error(const kita_state_s *s);

// Custom user-data
void  kita_set_context(kita_state_s *s, void *ctx);
void *kita_get_context(kita_state_s *s);

#endif
