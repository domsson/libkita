#include <stdio.h>     // fdopen(), FILE, ...
#include <stdlib.h>    // NULL, size_t, EXIT_SUCCESS, EXIT_FAILURE, ...
#include <unistd.h>    // pipe(), fork(), dup(), close(), _exit(), ...
#include <string.h>    // strlen()
#include <errno.h>     // errno
#include <fcntl.h>     // fcntl(), F_GETFL, F_SETFL, O_NONBLOCK
#include <spawn.h>     // posix_spawnp()
#include <wordexp.h>   // wordexp(), wordfree(), ...
#include <sys/epoll.h> // epoll_wait(), ... 
#include <sys/types.h> // pid_t
#include <sys/wait.h>  // waitpid()
#include <sys/ioctl.h> // ioctl(), FIONREAD
#include "execute.c"
#include "helpers.c"
#include "kita.h"

static volatile int running;   // Main loop control 
extern char **environ;         // Required to pass the environment to children

////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  PRIVATE FUNCTIONS                                                         //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

/*
 * Examines the given file descriptor for the number of bytes available for 
 * reading and returns that number. On error, -1 will be returned.
 */
static int
libkita_fd_data_avail(int fd)
{
	int bytes = 0;
	return ioctl(fd, FIONREAD, &bytes) == -1 ? -1 : bytes;
}

/*
 * Finds and returns the child with the given `pid` or NULL.
 */
kita_child_s*
libkita_child_get_by_pid(kita_state_s *state, pid_t pid)
{
	for (size_t i = 0; i < state->num_children; ++i)
	{	
		if (state->children[i]->pid == pid)
		{
			return state->children[i];
		}
	}
	return NULL;
}

/*
 * Find the index (array position) of the given child.
 * Returns the index position or -1 if no such child found.
 */
static int
libkita_child_get_idx(kita_state_s *state, kita_child_s *child)
{
	for (size_t i = 0; i < state->num_children; ++i)
	{
		if (state->children[i] == child)
		{
			return i;
		}
	}
	return -1;
}

/*
 * Get the file descriptor associated with the given stream.
 * Returns the file descriptor on success, -1 on error.
 */
static int
libkita_stream_get_fd(kita_stream_s *stream)
{
	if (stream->fp == NULL)
	{
		return -1;
	}
	return fileno(stream->fp);
}

/*
 * Checks if the stream `ios` of the child matches the given file descriptor.
 * Returns 1 in case of a match, 0 otherwise.
 */
static int
libkita_child_fd_has_type(kita_child_s *child, int fd, kita_ios_type_e ios)
{
	if (fd < 0)
	{
		return 0;
	}
	if (child->io[ios] == NULL)
	{
		return 0;
	}
	return libkita_stream_get_fd(child->io[ios]) == fd;
}

static kita_ios_type_e
libkita_child_fd_get_type(kita_child_s *child, int fd)
{
	if (libkita_child_fd_has_type(child, fd, KITA_IOS_IN))
	{
		return KITA_IOS_IN;
	}
	if (libkita_child_fd_has_type(child, fd, KITA_IOS_OUT))
	{
		return KITA_IOS_OUT;
	}	
	if (libkita_child_fd_has_type(child, fd, KITA_IOS_ERR))
	{
		return KITA_IOS_ERR;
	}
	return -1;
}

static kita_child_s*
libkita_child_by_fd(kita_state_s *state, int fd)
{
	kita_child_s *child = NULL;
	for (size_t i = 0; i < state->num_children; ++i)
	{
		child = state->children[i];

		if (libkita_child_fd_has_type(child, fd, KITA_IOS_IN))
		{
			return child;
		}
		if (libkita_child_fd_has_type(child, fd, KITA_IOS_OUT))
		{
			return child;
		}	
		if (libkita_child_fd_has_type(child, fd, KITA_IOS_ERR))
		{
			return child;
		}
	}
	return NULL;
}

/*
 * Get the child's file pointer for the stream specified by `ios`.
 * Returns the file pointer, which could be NULL.
 */
static FILE*
libkita_child_get_fp(kita_child_s *child, kita_ios_type_e ios)
{
	if (child->io[ios] == NULL)
	{
		return NULL;
	}
	return child->io[ios]->fp;
}

/*
 * Get the file descriptor for the child's stream specified by `ios`.
 * Returns the integer file descriptor on success, -1 on error.
 */
static int
libkita_child_get_fd(kita_child_s *child, kita_ios_type_e ios)
{
	if (child->io[ios] == NULL)
	{
		return -1;
	}
	if (child->io[ios]->fp == NULL)
	{
		return -1;
	}
	return fileno(child->io[ios]->fp);
}

static int
libkita_stream_set_buf_type(kita_stream_s *stream, kita_buf_type_e buf)
{
	// From the setbuf manpage:
	// > The setvbuf() function may be used only after opening a stream
	// > and before any other operations have been performed on it.

	if (stream->fp == NULL) // can't modify if not yet open
	{
		return -1;
	}
	
	if (setvbuf(stream->fp, NULL, buf, 0) != 0)
	{
		return -1;
	}

	stream->buf_type = buf;
	return 0;
}

/*
 * Closes the given stream via fclose().
 * Returns 0 on success, -1 if the stream wasn't open in the first place.
 */
static int
libkita_stream_close(kita_stream_s *stream)
{
	if (stream->fp == NULL)
	{
		return -1;
	}

	fclose(stream->fp);
	stream->fp = NULL;
	return 0;
}

/*
 * Create a kita_stream_s struct on the heap (malloc'd) and 
 * initialize it to the given stream type `ios` and buffer type `buf`. 
 * Returns the allocated structure or NULL if out of memory.
 */
static kita_stream_s*
libkita_stream_new(kita_ios_type_e ios)
{
	kita_stream_s *stream = malloc(sizeof(kita_stream_s));
	if (stream == NULL)
	{
		return NULL;
	}
	*stream = (kita_stream_s) { 0 };
	
	// file descriptors are, by default, blocking
	stream->blocking = 1;

	// set stream type and stream buffer type
	stream->ios_type = ios;
	stream->buf_type = (ios == KITA_IOS_ERR) ? KITA_BUF_NONE : KITA_BUF_LINE;

	return stream;
}

/*
 * Close the child's file pointers via fclose(), then set them to NULL.
 * Returns the number of file pointers that have been closed.
 */
static int
libkita_child_close(kita_child_s *child)
{
	int num_closed = 0;
	if (child->io[KITA_IOS_IN] != NULL)
	{
		num_closed += (libkita_stream_close(child->io[KITA_IOS_IN]) == 0);
	}
	if (child->io[KITA_IOS_OUT] != NULL)
	{
		num_closed += (libkita_stream_close(child->io[KITA_IOS_OUT]) == 0);
	}
	if (child->io[KITA_IOS_ERR] != NULL)
	{
		num_closed += (libkita_stream_close(child->io[KITA_IOS_ERR]) == 0);
	}
	return num_closed;
}

/*
 * Init the epoll instance for the given state.
 * Returns 0 on success, -1 on error.
 */
static int
libkita_init_epoll(kita_state_s *state)
{
	int epfd = epoll_create(1);
	if (epfd < 0)
	{
		return -1;
	}
	state->epfd = epfd;
	return 0;
}

static void
libkita_reap(kita_state_s *state)
{
	// waitpid() with WNOHANG will return:
	//  - PID of the child that has changed state, if any
	//  -  0  if there are relevant children, but none have changed state
	//  - -1  on error

	pid_t pid  = 0;
	int status = 0;
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
	{
		fprintf(stdout, "waitpid -> %d\n", pid);
		kita_child_s *child = libkita_child_get_by_pid(state, pid);
		if (child == NULL)
		{
			fprintf(stderr, "reaping child %d\n", pid);
			libkita_child_close(child); 
			child->pid = 0;
		}
	}
}

static int
libkita_handle_event(kita_state_s *state, struct epoll_event *epev)
{
	kita_child_s *child = libkita_child_by_fd(state, epev->data.fd);
	if (child == NULL)
	{
		return 0;
	}

	kita_event_s event = { 0 };
	event.child = child;
	event.fd    = epev->data.fd; 
	event.ios   = libkita_child_fd_get_type(child, epev->data.fd);

	// We've got data coming in
	if(epev->events & EPOLLIN)
	{
		event.size = libkita_fd_data_avail(event.fd);
		fprintf(stdout, "kita event: EPOLLIN on %d (%d bytes)\n", event.ios, event.size);

		if (event.ios == KITA_IOS_OUT)
		{
			state->cbs.child_stdout_data(state, &event);
		}
		if (event.ios == KITA_IOS_ERR)
		{
			state->cbs.child_stderr_data(state, &event);
		}
	}
	
	// We're ready to send data
	if (epev->events & EPOLLOUT)
	{
		// TODO
		fprintf(stdout, "kita event: EPOLLOUT\n");
	}
	
	// Server closed the connection
	if (epev->events & EPOLLRDHUP)
	{
		// TODO
		fprintf(stdout, "kita event: EPOLLRDHUP\n");
	}
	
	// Unexpected hangup on socket 
	if (epev->events & EPOLLHUP) // fires even if not added explicitly
	{
		// TODO
		fprintf(stdout, "kita event: EPOLLHUP\n");
	}

	// Socket error
	if (epev->events & EPOLLERR) // fires even if not added explicitly
	{
		// TODO
		fprintf(stdout, "kita event: EPOLLERR\n");
	}
	
	// Handled everything and no error occurred
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  PUBLIC FUNCTIONS                                                          //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

// TODO - do we need this as a _public_ function?
//      - what are the implication, if a user calls this
//        but doesn't unregister, etc. etc.?
int kita_child_close(kita_child_s *child)
{
	return libkita_child_close(child);
}

/*
 * Set the blocking behavior of stream `ios` according to `blk`.
 * Returns 0 on success, -1 on error.
 */
int kita_child_set_blocking(kita_child_s *child, kita_ios_type_e ios, int blocking)
{
	if (child->io[ios] == NULL)     // no such stream for this child
	{
		return -1;
	}
	if (child->io[ios]->fp == NULL) // can't modify if not yet open
	{
		return -1;
	}

	int fd = fileno(child->io[ios]->fp);
	int flags = fcntl(fd, F_GETFL, 0);

	if (flags == -1)
	{
		return -1;
	}
	if (blocking) // make blocking
	{
	  	flags &= ~O_NONBLOCK;
	}
	else          // make non-blocking
	{
		flags |=  O_NONBLOCK;
	}
	if (fcntl(fd, F_SETFL, flags) != 0)
	{
		return -1;
	}

	child->io[ios]->blocking = blocking;
	return 0;
}

/*
 * Get the blocking behavior of the child's stream specified by `ios`.
 * Returns 1 for blocking, 0 for nonblocking, -1 if there is no such stream.
 */
int kita_child_get_blocking(kita_child_s *child, kita_ios_type_e ios)
{
	if (child->io[ios] == NULL)
	{
		return -1;
	}
	return child->io[ios]->blocking;
}

/*
 * Set the child's stream, specified by `ios`, to the buffer type specified
 * via `buf`. Returns 0 on success, -1 on error.
 */
int kita_child_set_buf_type(kita_child_s *child, kita_ios_type_e ios, kita_buf_type_e buf)
{
	if (child->io[ios] == NULL)
	{
		return -1;
	}
	return libkita_stream_set_buf_type(child->io[ios], buf);
}

/*
 * Get the buffer type of the child's stream specified by `ios`.
 * Returns the buffer type or -1 if there is no such stream.
 */
kita_buf_type_e kita_child_get_buf_type(kita_child_s *child, kita_ios_type_e ios)
{
	if (child->io[ios] == NULL)
	{
		return -1;
	}
	
	return child->io[ios]->buf_type;
}

/*
 * Save a reference to `arg`, which will be used as additional argument 
 * when opening or running this child. Use `NULL` to clear the argument.
 */
void kita_child_set_arg(kita_child_s *child, char *arg)
{
	child->arg = arg;
}

char *kita_child_get_arg(kita_child_s *child)
{
	return child->arg;
}

void kita_child_set_context(kita_child_s *child, void *ctx)
{
	child->ctx = ctx;
}

void* kita_child_get_context(kita_child_s *child)
{
	return child->ctx;
}

void kita_set_context(kita_state_s *state, void *ctx)
{
	state->ctx = ctx;
}

void* kita_get_context(kita_state_s *state)
{
	return state->ctx;
}

/*
 * Register all events for the given child with the epoll file descriptor.
 * Returns the number of events registered.
 */
int kita_child_reg_events(kita_state_s *state, kita_child_s *child)
{
	int reg =  0;

	struct epoll_event ev = { 0 };
      
	ev.data.fd = libkita_child_get_fd(child, KITA_IOS_IN);
	ev.events = KITA_IOS_IN | EPOLLET;
	reg += (epoll_ctl(state->epfd, EPOLL_CTL_ADD, ev.data.fd, &ev) == 0);

	ev.data.fd = libkita_child_get_fd(child, KITA_IOS_OUT);
	ev.events = KITA_IOS_OUT | EPOLLET;
	reg += (epoll_ctl(state->epfd, EPOLL_CTL_ADD, ev.data.fd, &ev) == 0);

	ev.data.fd = libkita_child_get_fd(child, KITA_IOS_ERR);
	ev.events = KITA_IOS_ERR | EPOLLET;
	reg += (epoll_ctl(state->epfd, EPOLL_CTL_ADD, ev.data.fd, &ev) == 0);
	
	return reg;
}

/*
 * Removes all events for the given child from the epoll file descriptor.
 * Returns the number of events deleted.
 */
int kita_child_rem_events(kita_state_s *state, kita_child_s *child)
{
	int del =  0;
	int fd  = -1;
	
	fd = libkita_child_get_fd(child, KITA_IOS_IN);
	del += (epoll_ctl(state->epfd, EPOLL_CTL_DEL, fd, NULL) == 0);

	fd = libkita_child_get_fd(child, KITA_IOS_OUT);
	del += (epoll_ctl(state->epfd, EPOLL_CTL_DEL, fd, NULL) == 0);

	fd = libkita_child_get_fd(child, KITA_IOS_ERR);
	del += (epoll_ctl(state->epfd, EPOLL_CTL_DEL, fd, NULL) == 0);
	
	return del;
}

int kita_child_open(kita_child_s *child)
{
	if (child->pid > 0)
	{
		// ALREADY OPEN
		return -1;
	}

	if (empty(child->cmd))
	{
		// NO COMMAND GIVEN
		return -1;
	}

	// Construct the command, if there is an additional argument string
	char *cmd = NULL;
	if (child->arg)
	{
		size_t len = strlen(child->cmd) + strlen(child->arg) + 4;
		cmd = malloc(sizeof(char) * len);
		snprintf(cmd, len, "%s %s", child->cmd, child->arg);
	}
	
	// Execute the block and retrieve its PID
	child->pid = popen_noshell(
			cmd ? cmd : child->cmd, 
			child->io[KITA_IOS_IN]  ? &child->io[KITA_IOS_IN]->fp  : NULL,
			child->io[KITA_IOS_OUT] ? &child->io[KITA_IOS_OUT]->fp : NULL,
		        child->io[KITA_IOS_ERR] ? &child->io[KITA_IOS_ERR]->fp : NULL);
	free(cmd);

	// Check if that worked
	if (child->pid == -1)
	{
		// popen_noshell() failed to open it
		return -1;
	}
	
	// - Set the buffer type according to the stream's options
	// - Set the blocking behavior according to the stream's options
	// TODO these functions also check if child->io[...] exists - redundant?
	if (child->io[KITA_IOS_IN])
	{
		kita_child_set_buf_type(child, KITA_IOS_IN,  child->io[KITA_IOS_IN]->buf_type);
		kita_child_set_blocking(child, KITA_IOS_IN,  child->io[KITA_IOS_IN]->blocking);
	}
	if (child->io[KITA_IOS_OUT])
	{
		kita_child_set_buf_type(child, KITA_IOS_OUT, child->io[KITA_IOS_OUT]->buf_type);
		kita_child_set_blocking(child, KITA_IOS_OUT, child->io[KITA_IOS_OUT]->blocking);
	}
	if (child->io[KITA_IOS_ERR])
	{
		kita_child_set_buf_type(child, KITA_IOS_ERR, child->io[KITA_IOS_ERR]->buf_type);
		kita_child_set_blocking(child, KITA_IOS_ERR, child->io[KITA_IOS_ERR]->blocking);
	}
	
	return 0;
}

/*
 * Sends the SIGKILL signal to the child. SIGKILL can not be ignored 
 * and leads to immediate shut-down of the child process, no clean-up.
 * Returns 0 on success, -1 on error.
 */
int kita_child_kill(kita_child_s *child)
{
	if (child->pid < 2)
	{
		return -1;
	}
	
	// We do not set the child's PID to 0 here, because it seems
	// like the better approach to detect all child deaths via 
	// waitpid() or some other means (same approach for all).
	return kill(child->pid, SIGKILL);
}

/*
 * Sends the SIGTERM signal to the child. SIGTERM can be ignored or 
 * handled and allows the child to do clean-up before shutting down.
 * Returns 0 on success, -1 on error.
 */
int kita_child_term(kita_child_s *child)
{
	if (child->pid < 2)
	{
		return -1;
	}
	
	// We do not set the child's PID to 0 here, because the 
	// child might not immediately terminate (clean-up, etc). 
	// Instead, we should catch SIGCHLD, then use waitpid()
	// to determine the termination and to set PID to 0.
	return kill(child->pid, SIGTERM);
}

/*
 * Attempt to read from the child's stdout file pointer, and store the result, 
 * if any, in the child's `output` field.
 * TODO - give user option to select whether to read ...
 *        - ... everything
 *        - ... a specified number of bytes
 *        - ... the first line (if line buffered)
 *        - ... the last line  (if line buffered)
 *      - should this return an allocated buffer OR accept a buffer + size?
 */
char* kita_child_read(kita_child_s *child, kita_ios_type_e ios, char *buf, size_t len)
{
	if (ios == KITA_IOS_IN) // can't read from stdin
	{
		return NULL;
	}

	FILE *fp = libkita_child_get_fp(child, ios);

	//FILE *fp = child->io[ios]->fp;

	if (fp == NULL)
	{
		return NULL;
	}

	// TODO would it be nicer if we just allocated a buffer internally?
	//      i believe so...

	// TODO implement different solutions depending on the child's
	//      buffer type and blocking behavior!

	// TODO maybe use getline() instead? It allocates a suitable buffer!

	// TODO we need to figure out if all use-cases are okay with just 
	//      calling fgets() once; at least one use-case was using the
	//      while-loop approach; not sure if that might now break?
	//      In particular, isn't it bad if we don't consume all the 
	//      data that is available for read? But the issue is that if
	//      we use the while approach with live blocks or sparks, then 
	//      the while will keep on looping forever...

	/*
	size_t num_lines = 0;
	while (fgets(buf, len, child->fp[KITA_IOS_OUT]) != NULL)
	{
		++num_lines;
	}

	if (num_lines == 0)
	*/

	if (fgets(buf, len, fp) == NULL)
	{
		fprintf(stderr, "read_child(): fgets() failed: `%s`\n", child->cmd);
		if (feof(fp))
		{
			fprintf(stderr, "\t(EOF - nothing to read)\n");
		}
		if (ferror(fp))
		{
			if (errno == EAGAIN || errno == EWOULDBLOCK)
			{
				// Expected when trying to read from 
				// non-blocking streams with no data to read.
				fprintf(stderr, "\t(ERR - no data to read)\n");
			}
			else
			{
				// Some other error
				fprintf(stderr, "\t(ERR - %d)\n", errno);
			}
			clearerr(fp);
		}
		return NULL;
	}

	buf[strcspn(buf, "\n")] = 0; // Remove '\n'
	return buf;
}

/*
 * Writes the given `input` to the child's stdin stream.
 * Returns 0 on success, -1 on error.
 */
int kita_child_feed(kita_child_s *child, const char *input)
{
	// child doesn't have a stdin stream
	if (child->io[KITA_IOS_IN] == NULL)
	{
		return -1;
	}
	
	// child's stdin file pointer isn't open
	if (child->io[KITA_IOS_IN]->fp == NULL) 
	{
		return -1;
	}

	// no input given, or input is empty 
	if (empty(input))
	{
		return -1;
	}

	return (fputs(input, child->io[KITA_IOS_IN]->fp) == EOF) ? -1 : 0;
}

/*
 * Free the child's streams. Make sure to close them before.
 * TODO - shouldn't it be called libkita_child_free_streams() then?
 *      - what exactly is the purpose of this function?
 *      - rethink this... 
 */
void kita_child_free(kita_child_s *child)
{
	if (child->io[KITA_IOS_IN])
	{
		free(child->io[KITA_IOS_IN]);
		child->io[KITA_IOS_IN] = NULL;
	}
	if (child->io[KITA_IOS_OUT])
	{
		free(child->io[KITA_IOS_OUT]);
		child->io[KITA_IOS_OUT] = NULL;
	}
	if (child->io[KITA_IOS_ERR])
	{
		free(child->io[KITA_IOS_ERR]);
		child->io[KITA_IOS_ERR] = NULL;
	}
}

size_t kita_child_del(kita_state_s *state, kita_child_s *child)
{
	// find the array index of the given child
	int idx = libkita_child_get_idx(state, child);
	if (idx < 0)
	{
		// child not found, do nothing
		return state->num_children;
	}

	// reduce child counter by one
	--state->num_children;

	// free() the element where the given child was found
	free(state->children[idx]);
	state->children[idx] = NULL;
	
	// copy the ptr to the last element into this element
	state->children[idx] = state->children[state->num_children];

	// realloc() the array to the new size
	size_t new_size = state->num_children * sizeof(state->children);
	kita_child_s **children = realloc(state->children, new_size);
	if (children == NULL)
	{
		// realloc() failed, which means we're stuck with the old 
		// memory, which is too large by one element and now has 
		// a duplicate element (the last one and the one at `idx`),
		// which is annoying, but if we pretend the size to be one 
		// smaller than it actually is, then we should never find 
		// ourselves acidentally trying to access that last element;
		// and hopefully the next realloc() will success and fix it.
		// just in case, we set the last element to NULL.
		state->children[state->num_children] = NULL;
		return state->num_children; 
	}
	state->children = children;
	return state->num_children;
}

size_t kita_child_add(kita_state_s *state, kita_child_s *child)
{
	// array index for the new child
	int idx = state->num_children++;

	// increase array size
	size_t new_size = state->num_children * sizeof(state->children);
	kita_child_s **children = realloc(state->children, new_size);
	if (children == NULL)
	{
		return --state->num_children;
	}
	state->children = children;

	// add new child
	state->children[idx] = child;

	// return new number of children
	return state->num_children;
}

kita_child_s* kita_child_new(const char *cmd, int in, int out, int err)
{
	kita_child_s *child = malloc(sizeof(kita_child_s));
	if (child == NULL)
	{
		return NULL;
	}

	// zero-initialize
	*child = (kita_child_s) { 0 };


	// copy the command
	child->cmd = strdup(cmd);

	// create input/output streams as requested
	child->io[KITA_IOS_IN]  = in ? 	libkita_stream_new(KITA_IOS_IN)  : NULL;
	child->io[KITA_IOS_OUT] = out ?	libkita_stream_new(KITA_IOS_OUT) : NULL;
	child->io[KITA_IOS_ERR] = err ?	libkita_stream_new(KITA_IOS_ERR) : NULL;
	
	return child;
}


kita_calls_s* kita_get_callbacks(kita_state_s *state)
{
	return &state->cbs;
}

int kita_tick(kita_state_s *s, int timeout)
{
	struct epoll_event epev;
	
	// epoll_wait()/epoll_pwait() will return -1 if a signal is caught.
	// User code might catch "harmless" signals, like SIGWINCH, that are
	// ignored by default. This would then cause epoll_wait() to return
	// with -1, hence our main loop to come to a halt. This is not what
	// a user would expect; we should only come to a halt on "serious"
	// signals that would cause program termination/halt by default.
	// In order to achieve this, we tell epoll_pwait() to block all of
	// the signals that are ignored by default. For a list of signals:
	// https://en.wikipedia.org/wiki/Signal_(IPC)
	
	sigset_t sigset;
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGCHLD);  // default: ignore
	sigaddset(&sigset, SIGCONT);  // default: continue execution
	sigaddset(&sigset, SIGURG);   // default: ignore
	sigaddset(&sigset, SIGWINCH); // default: ignore

	// timeout = -1 -> block indefinitely, until events available
	// timeout =  0 -> return immediately, even if no events available
	int num_events = epoll_pwait(s->epfd, &epev, 1, timeout, &sigset);

	// An error has occured
	if (num_events == -1)
	{
		// The exact reason why epoll_wait failed can be queried through
		// errno; the possibilities include wrong/faulty parameters and,
		// more interesting, that a signal has interrupted epoll_wait().
		// Wrong parameters will either happen on the very first call or
		// not at all, but a signal could come in anytime. Either way, 
		// epoll_wait() failing doesn't necessarily mean that we lost 
		// the connection with the server. Some signals, like SIGSTOP 
		// can mean that we're simply supposed to stop execution until 
		// a SIGCONT is received. Hence, it seems like a good idea to 
		// leave it up to the user what to do, which means that we are
		// not going to quit/disconnect from IRC; we're simply going to
		// return -1 to indicate an issue. The user can then check the 
		// connection status and decide if they want to explicitly end 
		// the connection or keep it alive. One exception: if we can 
		// actually determine, right here, that the connection seems to
		// be down, then we'll set off the disconnect event handlers.
		// For this, we'll use tcpsnob_status().

		// Set the error accordingly:
		//  - KITA_ERR_EPOLL_SIG  if epoll_pwait() caught a signal
		//  - KITA_ERR_EPOLL_WAIT for any other error in epoll_wait()
		s->error = errno == EINTR ? KITA_ERR_EPOLL_SIG : KITA_ERR_EPOLL_WAIT;
		
		return -1;
	}
	
	/*
	// No events have occured
	if (num_events == 0)
	{
		return 0;
	}
	*/
	
	// Wait for children that died, if any
	// TODO - shouldn't this come AFTER libkita_handle_event()?
	//        otherwise we might get the "child_died" event before
	//        the last output of said child
	libkita_reap(s);

	return libkita_handle_event(s, &epev);
}

// TODO we need some more condition as to when we quit the loop?
int kita_loop(kita_state_s *s)
{
	while (kita_tick(s, -1) == 0)
	{
		fprintf(stdout, "tick... tock...\n");
		// Nothing to do here
	}
	// TODO - should we close all children here?
	//      - if so, we should also reap them!
	//      - but this means we'd need another round of epoll_wait?
	fprintf(stderr, "error code = %d\n", s->error);
	return 0; // TODO
}

int kita_loop_timed(kita_state_s *s, int timeout)
{
	while (kita_tick(s, timeout) == 0)
	{
		fprintf(stdout, "tick... tock...\n");
	}
	return 0;
}

kita_state_s* kita_init()
{
	// Allocate memory for the state struct
	kita_state_s *s = malloc(sizeof(kita_state_s));
	if (s == NULL) 
	{
		return NULL;
	}
	
	// Set the memory to a zero-initialized struct
	*s = (kita_state_s) { 0 };

	// Initialize an epoll instance
	if (libkita_init_epoll(s) != 0)
	{
		return NULL;
	}

	// Return a pointer to the created state struct
	return s;
}

////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  USER CODE                                                                 //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

void on_child_dead(kita_state_s *state, kita_event_s *event)
{
	fprintf(stdout, "on_child_dead()\n");
}

void on_child_data(kita_state_s *state, kita_event_s *event)
{
	size_t len = 1024;
	char buf[1024];
	kita_child_read(event->child, event->ios, buf, len);
	fprintf(stdout, "on_child_data(): %s\n", buf);
}

int main(int argc, char **argv)
{
	kita_state_s *state = kita_init();

	if (state == NULL)
	{
		return EXIT_FAILURE;
	}
	
	kita_calls_s *calls = kita_get_callbacks(state);
	
	calls->child_died        = on_child_dead;
	calls->child_stdout_data = on_child_data;

	kita_child_s *child_datetime = kita_child_new("~/.local/bin/candies/datetime", 0, 1, 0);
	kita_child_add(state, child_datetime);
	kita_child_open(child_datetime);
	kita_child_reg_events(state, child_datetime);
	
	kita_loop_timed(state, 1000);

	return EXIT_SUCCESS;
}

