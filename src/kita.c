#include <stdio.h>     // fdopen(), FILE, ...
#include <stdlib.h>    // NULL, size_t, EXIT_SUCCESS, EXIT_FAILURE, ...
#include <unistd.h>    // pipe(), fork(), dup(), close(), _exit(), ...
#include <string.h>    // strlen()
#include <errno.h>     // errno
#include <fcntl.h>     // fcntl(), F_GETFL, F_SETFL, O_NONBLOCK
#include <spawn.h>     // posix_spawnp()
#include <wordexp.h>   // wordexp(), wordfree(), ...
#include <sys/epoll.h> // epoll_create, epoll_wait(), ... 
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
static kita_child_s*
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

static kita_ios_type_e
libkita_child_fd_get_type(kita_child_s *child, int fd)
{
	for (int i = 0; i < 3; ++i)
	{
		if (child->io[i] && child->io[i]->fd == fd)
		{
			return (kita_ios_type_e) i;
		}
	}
	return -1;
}

static int
libkita_child_has_fd(kita_child_s *child, int fd)
{
	for (int i = 0; i < 3; ++i)
	{
		if (child->io[i] && child->io[i]->fd == fd)
		{
			return 1;
		}
	}
	return 0;
}

static kita_child_s*
libkita_child_by_fd(kita_state_s *state, int fd)
{
	for (size_t i = 0; i < state->num_children; ++i)
	{
		if (libkita_child_has_fd(state->children[i], fd))
		{
			return state->children[i];
		}

	}
	return NULL;
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
 * Register the given stream's file descriptor with the state's epoll instance.
 */
static int
libkita_stream_reg_ev(kita_state_s *state, kita_stream_s *stream)
{
	if (stream->fp == NULL) // we don't register a closed stream
	{
		return -1;
	}

	int fd = fileno(stream->fp);
	int ev = stream->ios_type == KITA_IOS_IN ? EPOLLOUT : EPOLLIN;

	struct epoll_event epev = { .events = ev | EPOLLET, .data.fd = fd };
	
	if (epoll_ctl(state->epfd, EPOLL_CTL_ADD, fd, &epev) == 0)
	{
		stream->registered = 1;
		return 0;
	}
	return -1;
}

/*
 * Remove the given stream's file descriptor from the state's epoll instance.
 */
static int
libkita_stream_rem_ev(kita_state_s *state, kita_stream_s *stream)
{
	if (epoll_ctl(state->epfd, EPOLL_CTL_DEL, stream->fd, NULL) == 0)
	{
		stream->registered = 0;
		return 0;
	}
	return -1;
}

/*
 * Register all events for the given child with the epoll file descriptor.
 * Returns the number of events registered.
 */
static int 
libkita_child_reg_events(kita_state_s *state, kita_child_s *child)
{
	int reg = 0;
	for (int i = 0; i < 3; ++i)
	{
		if (child->io[i])
		{
			reg += libkita_stream_reg_ev(state, child->io[i]) == 0;
		}
	}
	return reg;
}

/*
 * Removes all events for the given child from the epoll file descriptor.
 * Returns the number of events deleted.
 */
static int
libkita_child_rem_events(kita_state_s *state, kita_child_s *child)
{
	int rem = 0;
	for (int i = 0; i < 3; ++i)
	{
		if (child->io[i])
		{
			rem += libkita_stream_rem_ev(state, child->io[i]) == 0;
		}
	}
	return rem;
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
		stream->fd = -1;
		return -1;
	}

	fclose(stream->fp);
	stream->fp = NULL;
	stream->fd = -1;
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

	// file descriptor
	stream->fd = -1;
	
	// set stream type and stream buffer type
	stream->ios_type = ios;
	stream->buf_type = (ios == KITA_IOS_ERR) ? KITA_BUF_NONE : KITA_BUF_LINE;

	return stream;
}

static int
libkita_child_open(kita_child_s *child)
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
	
	// Get file descriptors from open file pointers
	for (int i = 0; i < 3; ++i)
	{
		if (child->io[i] && child->io[i]->fp)
		{
			child->io[i]->fd = fileno(child->io[i]->fp);
		}
	}
	
	return 0;
}

/*
 * Close the child's file pointers via fclose(), then set them to NULL.
 * Returns the number of file pointers that have been closed.
 */
static int
libkita_child_close(kita_child_s *child)
{
	int num_closed = 0;
	for (int i = 0; i < 3; ++i)
	{
		if (child->io[i] != NULL)
		{
			num_closed += (libkita_stream_close(child->io[i]) == 0);
		}
	}
	return num_closed;
}

static size_t
libkita_child_add(kita_state_s *state, kita_child_s *child)
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

	// mark new child as tracked
	state->children[idx]->state = state;

	// return new number of children
	return state->num_children;
}

/*
 * Removes this child from the state. The child will not be stopped or closed,
 * nor will its events be deleted from the state's epoll instance. 
 * Returns the new number of children tracked by the state.
 */
static size_t
libkita_child_del(kita_state_s *state, kita_child_s *child)
{
	// find the array index of the given child
	int idx = libkita_child_get_idx(state, child);
	if (idx < 0)
	{
		// child not found, do nothing
		return state->num_children;
	}

	// remove state reference from child
	child->state = NULL;

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
		// ourselves accidentally trying to access that last element;
		// and hopefully the next realloc() will succeed and fix it.
		// just in case, we set the last element to NULL.
		state->children[state->num_children] = NULL;
		return state->num_children; 
	}
	state->children = children;
	return state->num_children;
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

static int
libkita_dispatch_event(kita_state_s *state, kita_event_s *event)
{
	if (state->cbs[event->type] == NULL)
	{
		return -1;
	}
	state->cbs[event->type](state, event);
	return 0;
}

/*
 * Uses waitid() to figure out if the given child is alive or dead.
 * Returns 1 if child is alive, 0 if dead, -1 if status is unknown.
 */ 
static int
libkita_child_status(kita_child_s *child)
{
	siginfo_t info = { 0 };
	int options = WEXITED | WSTOPPED | WNOHANG | WNOWAIT;
	if (waitid(P_PID, child->pid, &info , options) == -1)
	{
		// waitid() error, status unknown
		return -1;
	}
	if (info.si_pid == 0) 
	{
		// no state change for PID, still running
 		return 1;
	}
	// we don't need to inspect info.si_code, because
	// we only wait for exited/stopped children anyway
	return 0;
}

/*
 * Uses waitpid() to identify children that have died. Dead children will be 
 * closed (by closing all of their streams) and their PID will be reset to 0. 
 * The REAPED event will be dispatched for each child reaped this way.
 * Returns the number of reaped children.
 */
static int
libkita_reap(kita_state_s *state)
{
	// waitpid() with WNOHANG will return:
	//  - PID of the child that has changed state, if any
	//  -  0  if there are relevant children, but none have changed state
	//  - -1  on error

	int reaped = 0;
	pid_t pid  = 0;
	int status = 0;
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
	{
		kita_child_s *child = libkita_child_get_by_pid(state, pid);
		if (child)
		{
			// remember the child's waitpid status
			child->status = status;

			// close the child's streams
			libkita_child_close(child); 

			// prepare the event struct
			kita_event_s event = { 0 };
			event.child = child;
			event.ios   = KITA_IOS_ALL;

			// dispatch close event
			event.type  = KITA_EVT_CHILD_CLOSED;
			libkita_dispatch_event(state, &event);

			// dispatch reap event
			event.type  = KITA_EVT_CHILD_REAPED;
			libkita_dispatch_event(state, &event);

			// finally, set the PID to 0
			child->pid = 0;

			++reaped;
		}
	}
	return reaped;
}

/*
 * Inspects all children, removing all of those that have been manually reaped 
 * by user code (indicated by their PID being 0), also removing their events. 
 */
static size_t
libkita_autoclean(kita_state_s *state)
{
	for (size_t i = 0; i < state->num_children; ++i)
	{
		if (state->children[i]->pid == 0)
		{
			// TODO
			// we need to send the REMOVE event _before_ we actually 
			// remove the child from the state, otherwise we would 
			// not be able to add a reference to the child to the 
			// event struct (it would be NULL!), hence the user 
			// would not know which child was removed. this means
			// that it is more of a "WILL_BE_REMOVED" event rather
			// than as "HAS_BEEN_REMOVED" event. gotta document that
			// very clearly somehow! ... or is there a better way?

			kita_event_s ev = { 0 };
			ev.child = state->children[i];
			ev.type  = KITA_EVT_CHILD_REMOVE;
			ev.ios   = KITA_IOS_NONE;
			ev.fd    = -1;
			libkita_dispatch_event(state, &ev);

			// remove child from epoll
			libkita_child_rem_events(state, state->children[i]);

			// remove child from state
			libkita_child_del(state, state->children[i]);
		}
	}
	return state->num_children;
}

/*
 * Inspects all children, terminating those that have been fully closed, 
 * possibly by user code (indicated by all of their streams being NULL).
 */
static int
libkita_autoterm(kita_state_s *state)
{
	int terminated = 0;
	for (size_t i = 0; i < state->num_children; ++i)
	{
		if (kita_child_is_open(state->children[i]) == 0)
		{
			terminated += (kita_child_term(state->children[i]) == 0);
		}
	}
	return terminated;
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

	// EPOLLIN: We've got data coming in
	if(epev->events & EPOLLIN)
	{
		event.type = KITA_EVT_CHILD_READOK; 
		event.size = libkita_fd_data_avail(event.fd);
		libkita_dispatch_event(state, &event);
		return 0;
	}
	
	// EPOLLOUT: We're ready to send data
	if (epev->events & EPOLLOUT)
	{
		event.type = KITA_EVT_CHILD_FEEDOK;
		libkita_dispatch_event(state, &event);
		return 0;
	}
	
	// EPOLLRDHUP: Server closed the connection
	// EPOLLHUP:   Unexpected hangup on socket 
	if (epev->events & EPOLLRDHUP || epev->events & EPOLLHUP)
	{
		// dispatch hangup event
		event.type = KITA_EVT_CHILD_HANGUP;
		libkita_dispatch_event(state, &event);

		// close the stream
		libkita_stream_rem_ev(state, child->io[event.ios]);
		libkita_stream_close(child->io[event.ios]);

		// create closed event by making a copy of the original
		kita_event_s event_closed = event;
		event_closed.type = KITA_EVT_CHILD_CLOSED;
		
		// dispatch closed event
		libkita_dispatch_event(state, &event_closed);
		return 0;
	}
	
	// EPOLLERR: Error on file descriptor (could also mean: stdin closed)
	if (epev->events & EPOLLERR) // fires even if not added explicitly
	{
		event.type = KITA_EVT_CHILD_ERROR;
		libkita_dispatch_event(state, &event);
	
		// event happened on stdin: stdin was probably closed
		// EBADF is set: file descriptor is not valid (anymore)
		if (event.ios == KITA_IOS_IN || errno == EBADF) 
		{
			libkita_stream_rem_ev(state, child->io[event.ios]);
			libkita_stream_close(child->io[event.ios]);

			// dispatch closed event
			event.type = KITA_EVT_CHILD_CLOSED;
			libkita_dispatch_event(state, &event);
		}
		return 0;
	}
	
	// Handled everything and no error occurred
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  PUBLIC FUNCTIONS                                                          //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

/*
 * Returns the number of open streams for this child or 0 if none are open.
 */
int 
kita_child_is_open(kita_child_s *child)
{
	int open = 0;
	for (int i = 0; i < 3; ++i)
	{
		if (child->io[i])
		{
			open += child->io[i]->fp != NULL;
		}
	}
	return open;
}

/*
 * Returns 1 if the child is still alive, 0 otherwise.
 */
int
kita_child_is_alive(kita_child_s *child)
{
	// PID of 0 means the child is dead or was never alive
	if (child->pid == 0)
	{
		return 0;
	}
	
	// TODO this can return -1 if waitid() failed, in which
	//      case we don't know if child is dead or alive...
	return libkita_child_status(child) == 1;
}

/*
 * Uses waitpid() to check if the child has terminated. If so, the child will 
 * be closed (by closing all of its streams) and its PID will be reset to 0. 
 * Returns the PID of the reaped child, 0 if the child wasn't reaped or -1 if 
 * the call to waitpid() encountered an error (inspect errno for details).
 * Note: this function is for children that are _untracked_ (have not been 
 *       added to a state); it will do nothing if the given child is tracked. 
 *       Also, no events (neither CLOSED nor REAPED) will be dispatched.
 */
int 
kita_child_reap(kita_child_s *child)
{
	// tracked children will be reaped automatically, abort 
	if (child->state)
	{
		return -1;
	}

	int pid = waitpid(child->pid, &child->status, WNOHANG);
	if (child->pid == pid)
	{
		// close the child's streams
		libkita_child_close(child); 

		// finally, set the PID to 0
		child->pid = 0;
	}
	return pid;
}

int
kita_child_skip(kita_child_s *child, kita_ios_type_e ios)
{
	if (ios == KITA_IOS_IN)         // can't seek stdin
	{
		return -1;
	}
	if (child->io[ios] == NULL)     // no such stream
	{
		return -1;
	}
	if (child->io[ios]->fp == NULL) // stream closed
	{
		return -1;
	}
	return fseek(child->io[ios]->fp, 0, SEEK_END);
}

/*
 * Closes all open streams of this child. If the child is tracked by a state, 
 * all events for the child's streams will also be removed. Note that closing 
 * the child will not automatically terminate it, however. Closing the child 
 * will merely close down all communication channels to and from the child; 
 * the child will continue to run; you should still receive a signal once the 
 * child terminates. If you want to stop the child, kill or terminate it.
 * Returns 0 on success, -1 on error.
 */
int
kita_child_close(kita_child_s *child)
{
	// if child is tracked, unregister its events 
	if (child->state)
	{
		libkita_child_rem_events(child->state, child);
	}

	// close all streams
	return libkita_child_close(child) > 0 ? 0 : -1;
}

/*
 * Set the blocking behavior of the given stream, where 0 means non-blcking 
 * and 1 means blocking. Returns 0 on success, -1 on error.
 */
int
libkita_stream_set_blocking(kita_stream_s *stream, int blocking)
{
	if (stream->fp == NULL) // can't modify if not yet open
	{
		return -1;
	}

	if (stream->fd < 2) // can't modify without valid file descriptor
	{
		return -1;
	}

	//int fd = fileno(stream->fp);
	int flags = fcntl(stream->fd, F_GETFL, 0);

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
	if (fcntl(stream->fd, F_SETFL, flags) != 0)
	{
		return -1;
	}

	return 0;
}

/*
 * Set the child's stream, specified by `ios`, to the buffer type specified
 * via `buf`. Returns 0 on success, -1 on error.
 */
int
kita_child_set_buf_type(kita_child_s *child, kita_ios_type_e ios, kita_buf_type_e buf)
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
kita_buf_type_e
kita_child_get_buf_type(kita_child_s *child, kita_ios_type_e ios)
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
void
kita_child_set_arg(kita_child_s *child, char *arg)
{
	child->arg = arg;
}

char*
kita_child_get_arg(kita_child_s *child)
{
	return child->arg;
}

void
kita_child_set_context(kita_child_s *child, void *ctx)
{
	child->ctx = ctx;
}

void*
kita_child_get_context(kita_child_s *child)
{
	return child->ctx;
}

kita_state_s*
kita_child_get_state(kita_child_s *child)
{
	return child->state;
}

void
kita_set_context(kita_state_s *state, void *ctx)
{
	state->ctx = ctx;
}

void*
kita_get_context(kita_state_s *state)
{
	return state->ctx;
}


/*
 * Opens (runs) the given child. If the child is tracked by the state, events 
 * for all opened streams will automatically be registered as well.
 * Returns 0 on success, -1 on error.
 */
int
kita_child_open(kita_child_s *child)
{
	int open = libkita_child_open(child);
	
	// if opening failed, return error code
	if (open < 0)
	{
		return open;
	}
	
	// make stdout and stderr streams non-blocking
	if (child->io[KITA_IOS_OUT])
	{
		libkita_stream_set_blocking(child->io[KITA_IOS_OUT], 0);
	}
	if (child->io[KITA_IOS_ERR])
	{
		libkita_stream_set_blocking(child->io[KITA_IOS_ERR], 0);
	}

	// if child is tracked, register events for it
	if (child->state)
	{
		libkita_child_reg_events(child->state, child);
	}
	return 0;
}

/*
 * Sends the SIGKILL signal to the child. SIGKILL can not be ignored 
 * and leads to immediate shut-down of the child process, no clean-up.
 * Returns 0 on success, -1 on error.
 */
int
kita_child_kill(kita_child_s *child)
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
int
kita_child_term(kita_child_s *child)
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

size_t
libkita_stream_read(kita_stream_s *stream, char *buf, size_t len)
{
	// TODO implement
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
char*
kita_child_read(kita_child_s *child, kita_ios_type_e ios, char *buf, size_t len)
{
	if (ios == KITA_IOS_IN) // can't read from stdin
	{
		return NULL;
	}

	if (child->io[ios] == NULL) // no such stream
	{
		return NULL;
	}

	if (child->io[ios]->fp == NULL) // stream closed
	{
		return NULL;
	}

	// for convenience
	FILE *fp = child->io[ios]->fp;

	// TODO would it be nicer if we just allocated a buffer internally?
	//      i believe so...

	// TODO implement different solutions depending on the child's
	//      buffer type?

	// TODO maybe use getline() instead? It allocates a suitable buffer!

	// TODO we need to figure out if all use-cases are okay with just 
	//      calling fgets() once; at least one use-case was using the
	//      while-loop approach; not sure if that might now break?
	//      In particular, isn't it bad if we don't consume all the 
	//      data that is available for read? But the issue is that if
	//      we use the while approach with live blocks or sparks, then 
	//      the while will keep on looping forever...

	// TODO maybe we can put this to use: libkita_fd_data_avail(int fd)
	
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
int
kita_child_feed(kita_child_s *child, const char *input)
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
 * Dynamically allocates a kita child and returns a pointer to it.
 * Returns NULL in case malloc() failed (out of memory).
 */
kita_child_s*
kita_child_new(const char *cmd, int in, int out, int err)
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

/*
 * TODO documentation ...
 * Returns the new number of children tracked by the kita state.
 */
int
kita_child_add(kita_state_s *state, kita_child_s *child)
{
	// child is already tracked (by this or another state)
	if (child->state)
	{
		// TODO set/return error code
		return -1;
	}
	return (int) libkita_child_add(state, child);
}

/*
 * Removes this child from the state. Any registered events will be removed 
 * in the process. However, the child will not be stopped or closed; it is 
 * up to the user to do that before calling this functions.
 * Returns the new number of children monitored by the state.
 */
int
kita_child_del(kita_state_s *state, kita_child_s *child)
{
	// can't delete untracked child, duh
	if (child->state == NULL)
	{
		// TODO set/return error code
		return -1;
	}
	
	// remove child from epoll
	libkita_child_rem_events(state, child);

	// remove child from state
	return (int) libkita_child_del(state, child);
}

/*
 * Returns the option specified by `opt`, either 0 or 1.
 * If the specified option doesn't exist, -1 is returned.
 */
char
kita_get_option(kita_state_s *state, kita_opt_type_e opt)
{
	// invalid option type
	if (opt < 0 || opt >= KITA_OPT_COUNT)
	{
		return -1; 
	}
	return state->options[opt];
}

/*
 * Sets the option specified by `opt` to `val`, where val is 0 or 1.
 * For any value greater than 1, the option will be set to 1.
 */
void
kita_set_option(kita_state_s *state, kita_opt_type_e opt, unsigned char val)
{
	// invalid option type
	if (opt < 0 || opt >= KITA_OPT_COUNT)
	{
		return;
	}
	state->options[opt] = (val > 0); // limit to [0, 1]
}

int
kita_set_callback(kita_state_s *state, kita_evt_type_e type, kita_call_c cb)
{
	// invalid event type
	if (type < 0 || type >= KITA_EVT_COUNT)
	{
		return -1;
	}
	// set the callback
	state->cbs[type] = cb;
	return 0;
}

int
libkita_poll(kita_state_s *s, int timeout)
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
		// not at all, but a signal could come in anytime. Some signals, 
		// like SIGSTOP, can mean that we're simply supposed to stop 
		// execution until a SIGCONT is received. Hence, it seems like 
		// a good idea to leave it up to the user what to do, which 
		// means that we might want to return -1 to indicate an issue. 
		// The user can then check errno and decide if they want to 
		// keep going / start again or stop for good.
		//
		// Set the error accordingly:
		//  - KITA_ERR_EPOLL_SIG  if epoll_pwait() caught a signal
		//  - KITA_ERR_EPOLL_WAIT for any other error in epoll_wait()
		s->error = errno == EINTR ? KITA_ERR_EPOLL_SIG : KITA_ERR_EPOLL_WAIT;
		
		return -1;
	}

	libkita_handle_event(s, &epev); // TODO what to do with the return val?
	return 0;
}

int
kita_tick(kita_state_s *state, int timeout)
{
	// wait for child events via epoll_pwait()
	libkita_poll(state, timeout);
	
	// reap dead children via waitpid()
	libkita_reap(state);

	// remove children that terminated without us noticing
	if (state->options[KITA_OPT_AUTOCLEAN])
	{
		libkita_autoclean(state);
	}

	// terminate children that were closed without us noticing
	if (state->options[KITA_OPT_AUTOTERM])
	{
		libkita_autoterm(state);
	}

	return 0; // TODO
}

// TODO we need some more condition as to when we quit the loop?
int
kita_loop(kita_state_s *s)
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

int
kita_loop_timed(kita_state_s *s, int timeout)
{
	while (kita_tick(s, timeout) == 0)
	{
		fprintf(stdout, "tick... tock...\n");
	}
	return 0;
}

kita_state_s* 
kita_init()
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

void on_child_reap(kita_state_s *state, kita_event_s *event)
{
	fprintf(stdout, "on_child_reap(): PID %d\n", event->child->pid);
}

void on_child_dead(kita_state_s *state, kita_event_s *event)
{
	fprintf(stdout, "on_child_dead(): PID %d\n", event->child->pid);
}

void on_child_data(kita_state_s *state, kita_event_s *event)
{
	size_t len = 1024;
	char buf[1024];
	kita_child_read(event->child, event->ios, buf, len);
	fprintf(stdout, "on_child_data(): PID %d\n", event->child->pid);
	fprintf(stdout, "> %s\n", buf);
}

int main(int argc, char **argv)
{
	kita_state_s *state = kita_init();

	if (state == NULL)
	{
		return EXIT_FAILURE;
	}
	
	kita_set_callback(state, KITA_EVT_CHILD_REAPED, on_child_reap);
	kita_set_callback(state, KITA_EVT_CHILD_HANGUP, on_child_dead);
	kita_set_callback(state, KITA_EVT_CHILD_READOK, on_child_data);

	kita_child_s *child_datetime = kita_child_new("~/.local/bin/candies/datetime -m", 0, 1, 0);
	kita_child_add(state, child_datetime);
	kita_child_open(child_datetime);
	
	kita_loop_timed(state, 1000);

	return EXIT_SUCCESS;
}

