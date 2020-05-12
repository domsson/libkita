#ifndef LIBKITA_H
#define LIBKITA_H

#include <unistd.h> // STDOUT_FILENO, STDIN_FILENO, STDERR_FILENO

#define KITA_NAME      "libkita"
#define KITA_URL       "https://github.com/domsson/libkita"
#define KITA_VER_MAJOR  0
#define KITA_VER_MINOR  1
#define KITA_VER_PATCH  0

#define KITA_BUFFER_SIZE 2048

#define KITA_MS_PER_S 1000

// Convenience
#define KITA_STDIN  STDIN_FILENO
#define KITA_STDOUT STDOUT_FILENO
#define KITA_STDERR STDERR_FILENO

// Errors
#define KITA_ERR_NONE            0
#define KITA_ERR_OTHER          -1
#define KITA_ERR_EPOLL_CREATE   -8
#define KITA_ERR_EPOLL_CTL      -9
#define KITA_ERR_EPOLL_WAIT    -10 // epoll_pwait() error
#define KITA_ERR_EPOLL_SIG     -11 // epoll_pwait() caught a signal

/*
 * Structs 
 */

struct kita_state;
struct kita_child;
struct kita_event;
struct kita_calls;

typedef struct kita_state kita_state_s;
typedef struct kita_child kita_child_s;
typedef struct kita_event kita_event_s;
typedef struct kita_calls kita_calls_s;

typedef void (*kita_call)(kita_state_s *s, kita_event_s *e);

struct kita_calls
{
	// TODO let's rethink these names...
	kita_call child_born;
	kita_call child_died;
	kita_call child_data;
	// TODO what else?
};

struct kita_child
{
	char *cmd;             // command/binary to run (could have arguments)
	char *arg;             // additional argument string (optional)
	pid_t pid;             // process ID

	FILE *fp[3];           // stdin/stdout/stderr file pointers

	//char *output;          // output of the last invocation

	double last_open;      // time of last invocation (0.0 for never)
	double last_read;      // time of last read from stdout (TODO what about stderr)
	unsigned ready : 1;    // fd has new data available for reading TODO maybe make it int and save the fp index that is ready?
};

struct kita_event
{
	kita_child_s *child;     // pointer to the child process struct 
	int stream : 3;          // stdin, stdout, stderr?
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

// Clean-up and shut-down
void kita_kill(kita_state_s *s);
void kita_free(kita_state_s *s);

// Retrieval of data from the twirc state
int kita_get_last_error(const kita_state_s *s);

// Custom user-data
void  kita_set_context(kita_state_s *s, void *ctx);
void *kita_get_context(kita_state_s *s);

#endif
