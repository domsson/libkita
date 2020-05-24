#ifndef LIBKITA_H
#define LIBKITA_H

#include <stdio.h>  // _IONBF, _IOLBF, _IOFBF
#include <unistd.h> // STDOUT_FILENO, STDIN_FILENO, STDERR_FILENO

//
// DEFINES
//

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
#define KITA_ERR_NONE              0
#define KITA_ERR_OTHER            -1
#define KITA_ERR_EPOLL_CREATE     -8
#define KITA_ERR_EPOLL_CTL        -9
#define KITA_ERR_EPOLL_WAIT      -10 // epoll_pwait() error
#define KITA_ERR_EPOLL_SIG       -11 // epoll_pwait() caught a signal
#define KITA_ERR_WAIT            -20 // wait(), waitpid() or waidid() error
#define KITA_ERR_CHILD_UNKNOWN   -30
#define KITA_ERR_CHILD_TRACKED   -31
#define KITA_ERR_CHILD_UNTRACKED -32
#define KITA_ERR_CHILD_OPEN      -33
#define KITA_ERR_CHILD_CLOSED    -34
#define KITA_ERR_CHILD_ALIVE     -35
#define KITA_ERR_CHILD_DEAD      -36

//
// ENUMS 
//

enum kita_ios_type {
	KITA_IOS_NONE = -1,
	KITA_IOS_IN   = STDIN_FILENO,  // 0
	KITA_IOS_OUT  = STDOUT_FILENO, // 1
	KITA_IOS_ERR  = STDERR_FILENO, // 2
	KITA_IOS_ALL
};

enum kita_buf_type {
	KITA_BUF_NONE = _IONBF,  // 0x0004
	KITA_BUF_LINE = _IOLBF,  // 0x0040
	KITA_BUF_FULL = _IOFBF   // 0x0000
};

enum kita_evt_type {
	KITA_EVT_CHILD_OPENED,   // child was opened TODO not sure we need this
	KITA_EVT_CHILD_CLOSED,   // child was closed 
	KITA_EVT_CHILD_REAPED,   // child was reaped
	KITA_EVT_CHILD_HANGUP,   // child has hung up TODO this and 'EXITED' are kinda same?
	KITA_EVT_CHILD_EXITED,   // child has exited  TODO this and 'HANGUP' are kinda same?
	KITA_EVT_CHILD_FEEDOK,   // child is ready to be fed data
	KITA_EVT_CHILD_READOK,   // child has data available to read
	KITA_EVT_CHILD_REMOVE,   // child is about to be removed from state
	KITA_EVT_CHILD_ERROR,    // and error occurred
	KITA_EVT_COUNT
};

enum kita_opt_type {
	KITA_OPT_AUTOCLEAN,      // automatically remove reaped children?
	KITA_OPT_AUTOTERM,       // automatically terminate fully closed children?
	KITA_OPT_AUTOEVENTS,     // automatically register events when opening children?
	KITA_OPT_COUNT
};

typedef enum kita_ios_type kita_ios_type_e;
typedef enum kita_buf_type kita_buf_type_e;
typedef enum kita_evt_type kita_evt_type_e;
typedef enum kita_opt_type kita_opt_type_e;

//
// STRUCTS 
//

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

typedef void (*kita_call_c)(kita_state_s *s, kita_event_s *e);

struct kita_stream
{
	FILE *fp;
	int   fd;

	kita_ios_type_e ios_type;
	kita_buf_type_e buf_type;
	unsigned registered : 1;  // child registered with epoll? TODO do we need this?
};

struct kita_child
{
	char *cmd;               // command/binary to run (could have arguments)
	char *arg;               // additional argument string (optional)
	pid_t pid;               // process ID

	kita_stream_s *io[3];    // stream objects for stdin, stdout, stderr
	int status;              // status returned by waitpid(), if any

	kita_state_s *state;     // tracking state, if any

	void *ctx;               // user data
};

struct kita_event
{
	kita_child_s *child;     // associated child process
	kita_evt_type_e type;    // event type
	kita_ios_type_e ios;     // stdin, stdout, stderr?
	int fd;                  // file descriptor for the relevant child's stream
	int size;                // number of bytes available for reading
};

struct kita_state
{
	kita_child_s **children; // child processes
	size_t num_children;     // num of child processes

	kita_call_c cbs[KITA_EVT_COUNT]; // event callbacks

	int epfd;                // epoll file descriptor
	sigset_t sigset;         // signals to be ignored by epoll_wait
	int error;               // last error that occured
	unsigned char options[KITA_OPT_COUNT]; // boolean options

	void *ctx;               // user data ('context')
};

//
// FUNCTIONS
//

// Initialization
kita_state_s *kita_init();
int kita_set_callback(kita_state_s *s, kita_evt_type_e type, kita_call_c cb);

// Main flow control
int kita_loop(kita_state_s *s);
int kita_tick(kita_state_s *s, int timeout);

// Children: creating, deleting, registering
kita_child_s* kita_child_new(const char *cmd, int in, int out, int err);
int           kita_child_add(kita_state_s *s, kita_child_s *c);
int           kita_child_del(kita_state_s *s, kita_child_s *c);

void kita_child_free(kita_child_s **c); // TODO ?

// Children: setting and getting options
int           kita_child_set_buf_type(kita_child_s *c, kita_ios_type_e ios, kita_buf_type_e buf);
void          kita_child_set_context(kita_child_s *c, void *ctx);
void         *kita_child_get_context(kita_child_s *c);
void          kita_child_set_arg(kita_child_s *c, char *arg);
char         *kita_child_get_arg(kita_child_s *c);
kita_state_s *kita_child_get_state(kita_child_s *c);
//FILE *kita_child_get_fp(kita_child_s *c, kita_ios_type_e ios);
//int   kita_child_get_fd(kita_child_s *c, kita_ios_type_e ios);

// Children: opening, reading, writing, killing
int   kita_child_feed(kita_child_s *c, const char *str);
char *kita_child_read(kita_child_s *c, kita_ios_type_e n, char *buf, size_t len);
int   kita_child_skip(kita_child_s *c, kita_ios_type_e n); // TODO implement
int   kita_child_open(kita_child_s *c);
int   kita_child_close(kita_child_s *c); 
int   kita_child_reap(kita_child_s *c);
int   kita_child_kill(kita_child_s *c);
int   kita_child_term(kita_child_s *c);

// Children: inquire, status
int kita_child_is_open(kita_child_s *c);
int kita_child_is_alive(kita_child_s *c);

// Clean-up and shut-down
void kita_kill(kita_state_s *s); // TODO
void kita_free(kita_state_s *s); // TODO

void kita_set_option(kita_state_s *s, kita_opt_type_e opt, unsigned char val);
char kita_get_option(kita_state_s *s, kita_opt_type_e opt);

// Custom user-data
void  kita_set_context(kita_state_s *s, void *ctx);
void *kita_get_context(kita_state_s *s);

// Retrieval of data from the twirc state
int kita_get_last_error(const kita_state_s *s);

#endif
