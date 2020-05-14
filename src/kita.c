#include <stdio.h>     // fdopen(), FILE, ...
#include <stdlib.h>    // NULL, size_t, EXIT_SUCCESS, EXIT_FAILURE, ...
#include <unistd.h>    // pipe(), fork(), dup(), close(), _exit(), ...
#include <string.h>    // strlen()
#include <signal.h>    // sigaction(), ... 
#include <errno.h>     // errno
#include <fcntl.h>     // fcntl(), F_GETFL, F_SETFL, O_NONBLOCK
#include <spawn.h>     // posix_spawnp()
#include <wordexp.h>   // wordexp(), wordfree(), ...
#include <sys/epoll.h> // epoll_wait(), ... 
#include <sys/types.h> // pid_t
#include <sys/wait.h>  // waitpid()
#include "helpers.c"
#include "kita.h"

static volatile int running;   // Main loop control 
static volatile int handled;   // The last signal that has been handled 
static volatile int sigchld;   // SIGCHLD has been received, please handle
static volatile int sigpipe;   // SIGPIPE has been received, please handle

extern char **environ; // Required to pass the environment to children

int kita_child_has_io(kita_child_s *child, kita_ios_type_e ios)
{
	return child->io[ios] != NULL;
}

/*
 * Get the child's file pointer for the stream specified by `ios`.
 * Returns the file pointer, which could be NULL.
 */
FILE *kita_child_get_fp(kita_child_s *child, kita_ios_type_e ios)
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
int kita_child_get_fd(kita_child_s *child, kita_ios_type_e ios)
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

/*
 * Set the relevant file descriptor's blocking behavior according to `blk`.
 * Returns 0 on success, -1 on error.
 */
int kita_child_set_blocking(kita_child_s *child, kita_ios_type_e ios, int blocking)
{
	if (child->io[ios] == NULL)
	{
		return -1;
	}
	if (child->io[ios]->fp == NULL) // can't modify if not yet open
	{
		// remember for later (when opening)
		child->io[ios]->blocking = 1;
		return 0;
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
	return fcntl(fd, F_SETFL, flags);
}

/*
 * Set the child's stream, specified by `ios`, to the buffer type specified
 * via `buf`. Returns 0 on success, -1 on error.
 */
int kita_child_set_buf_type(kita_child_s *child, kita_ios_type_e ios, kita_buf_type_e buf)
{
	// From the setbuf manpage:
	// > The setvbuf() function may be used only after opening a stream
	// > and before any other operations have been performed on it.
	if (child->io[ios] == NULL)
	{
		return -1;
	}
	if (child->io[ios]->fp == NULL) // can't modify if not yet open
	{
		// remember for later (when opening)
		child->io[ios]->buf_type = buf;
		return 0;
	}
	if (child->io[ios]->last > 0.0) // can't modify if already used
	{
		return -1;
	}

	child->io[ios]->buf_type = buf;
	return setvbuf(child->io[ios]->fp, NULL, buf, 0);
}

/*
 * TODO we're using execvp() and posix_spawnp() instead of execv() and 
 *      posix_spawn(). The difference is that the latter expect an absolute 
 *      or relative file path to the executable, while the former expect to 
 *      simply receive a filename which will then be searched for in PATH.
 *      The question is, which one actually makes more sense for us to use?
 *      Can the former _also_ handle file paths? Or do we need to look at 
 *      the commands given, figure out if they are a path, then call one or 
 *      the other function accordingly? Some more testing is required here!
 */

/*
 * Opens the process `cmd` similar to popen() but does not invoke a shell.
 * Instead, wordexp() is used to expand the given command, if necessary.
 * If successful, the process id of the new process is being returned and the 
 * given FILE pointers are set to streams that correspond to pipes for reading 
 * and writing to the child process, accordingly. Hand in NULL for pipes that
 * should not be used. On error, -1 is returned. Note that the child process 
 * might have failed to execute the given `cmd` (and therefore ended exection); 
 * the return value of this function only indicates whether the child process 
 * was successfully forked or not.
 */
pid_t popen_noshell(const char *cmd, FILE **in, FILE **out, FILE **err)
{
	if (!cmd || !strlen(cmd))
	{
		return -1;
	}

	// 0 = read end of pipes, 1 = write end of pipes
	int pipe_stdin[2];
	int pipe_stdout[2];
	int pipe_stderr[2];

	if (in && (pipe(pipe_stdin) < 0))
	{
		return -1;
	}
	if (out && (pipe(pipe_stdout) < 0))
	{
		return -1;
	}
	if (err && (pipe(pipe_stderr) < 0))
	{
		return -1;
	}

	pid_t pid = fork();
	if (pid == -1)
	{
		return -1;
	}
	else if (pid == 0) // child
	{
		// redirect stdin to the read end of this pipe
		if (in)
		{
			if (dup2(pipe_stdin[0], STDIN_FILENO) == -1)
			{
				_exit(-1);
			}
			close(pipe_stdin[1]); // child doesn't need write end
		}
		// redirect stdout to the write end of this pipe
		if (out)
		{
			if (dup2(pipe_stdout[1], STDOUT_FILENO) == -1)
			{
				_exit(-1);
			}
			close(pipe_stdout[0]); // child doesn't need read end
		}
		// redirect stderr to the write end of this pipe
		if (err)
		{
			if (dup2(pipe_stderr[1], STDERR_FILENO) == -1)
			{
				_exit(-1);
			}
			close(pipe_stderr[0]); // child doesn't need read end
		}

		wordexp_t p;
		if (wordexp(cmd, &p, 0) != 0)
		{
			_exit(-1);
		}
	
		// Child process could not be run (errno has more info)	
		if (execvp(p.we_wordv[0], p.we_wordv) == -1)
		{
			_exit(-1);
		}
		_exit(1);
	}
	else // parent
	{
		if (in)
		{
			close(pipe_stdin[0]);  // parent doesn't need read end
			*in = fdopen(pipe_stdin[1], "w");
		}
		if (out)
		{
			close(pipe_stdout[1]); // parent doesn't need write end
			*out = fdopen(pipe_stdout[0], "r");
		}
		if (err)
		{
			close(pipe_stderr[1]); // parent doesn't need write end
			*err = fdopen(pipe_stderr[0], "r");
		}
		return pid;
	}
}

/*
 * Run the given command via posix_spawnp() in a 'fire and forget' manner.
 * Returns the PID of the spawned process or -1 if running it failed.
 */
pid_t run_cmd(const char *cmd)
{
	// Return early if cmd is NULL or empty
	if (cmd == NULL || cmd[0] == '\0')
	{
		return -1;
	}

	// Try to parse the command (expand symbols like . and ~ etc)
	wordexp_t p;
	if (wordexp(cmd, &p, 0) != 0)
	{
		return -1;
	}
	
	// Spawn a new child process with the given command
	pid_t pid;
	int res = posix_spawnp(&pid, p.we_wordv[0], NULL, NULL, p.we_wordv, environ);
	wordfree(&p);
	
	// Return the child's PID on success, -1 on failure
	return (res == 0 ? pid : -1);
}

/*
 * Deletes all events for the given child from the epoll file descriptor.
 * Returns the number of events deleted.
 */
int libkita_child_del_event(kita_state_s *state, kita_child_s *child)
{
	int del =  0;
	int fd  = -1;
	
	fd = kita_child_get_fd(child, KITA_IOS_IN);
	del += (epoll_ctl(state->epfd, EPOLL_CTL_DEL, fd, NULL) == 0);

	fd = kita_child_get_fd(child, KITA_IOS_OUT);
	del += (epoll_ctl(state->epfd, EPOLL_CTL_DEL, fd, NULL) == 0);

	fd = kita_child_get_fd(child, KITA_IOS_ERR);
	del += (epoll_ctl(state->epfd, EPOLL_CTL_DEL, fd, NULL) == 0);
	
	return del;
}

/*
 * Register all events for the given child with the epoll file descriptor.
 * Returns the number of events registered.
 */
int libkita_child_reg_event(kita_state_s *state, kita_child_s *child)
{
	int reg =  0;
	int fd  = -1;

	struct epoll_event ev = { 0 };
	ev.data.ptr = (void *) child;
      
	fd = kita_child_get_fd(child, KITA_IOS_IN);
	ev.events = KITA_IOS_IN | EPOLLET;
	reg += (epoll_ctl(state->epfd, EPOLL_CTL_ADD, fd, &ev) == 0);

	fd = kita_child_get_fd(child, KITA_IOS_OUT);
	ev.events = KITA_IOS_OUT | EPOLLET;
	reg += (epoll_ctl(state->epfd, EPOLL_CTL_ADD, fd, &ev) == 0);

	fd = kita_child_get_fd(child, KITA_IOS_ERR);
	ev.events = KITA_IOS_ERR | EPOLLET;
	reg += (epoll_ctl(state->epfd, EPOLL_CTL_ADD, fd, &ev) == 0);
	
	return reg;
}



// TODO would be nice if we didn't have to hand in `in`, `out` and `err`
int kita_child_open(kita_state_s *state, kita_child_s *child)
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
	
	// register the child with epoll
	libkita_child_reg_event(state, child);

	return 0;
}

int libkita_stream_close(kita_stream_s *stream)
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
 * Close the child's file pointers via fclose(), then set them to NULL.
 * Returns the number of file pointers that have been closed.
 */
int kita_child_close(kita_child_s *child)
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
char *kita_child_read(kita_child_s *child, kita_ios_type_e ios, char *buf, size_t len)
{
	if (ios == KITA_IOS_IN) // can't read from stdin
	{
		return NULL;
	}

	FILE *fp = kita_child_get_fp(child, ios);
	if (fp == NULL)
	{
		return NULL;
	}

	// TODO maybe use getline() instead? It allocates a suitable buffer!
	// char *buf = malloc(len);

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

	//child->last_read = get_time();
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

kita_child_s *kita_child_add(kita_state_s *state, kita_child_s *child)
{
	// array index for the new child
	int current = state->num_children;

	// increase array size and add new child
	state->num_children += 1;
	state->children = realloc(state->children, state->num_children); // TODO error checking
	state->children[current] = *child;
	

	return &state->children[current];
}

kita_stream_s *libkita_stream_init(kita_ios_type_e ios, kita_buf_type_e buf)
{
	kita_stream_s *stream = malloc(sizeof(kita_stream_s));
	if (stream == NULL)
	{
		return NULL;
	}
	*stream = (kita_stream_s) { 0 };

	stream->ios_type = ios;
	stream->buf_type = buf;

	return stream;
}

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

kita_child_s *kita_child_make(kita_state_s *state, const char *cmd, int in, int out, int err)
{
	// We could create a struct on the stack and use kita_child_add(),
	// but that means we're creating an additional copy for no good
	// reason, which I'd rather avoid. Hence, let's just have a bit of 
	// duplicate code but in turn not have to make that useless copy.

	int current = state->num_children;

	state->num_children += 1;
	state->children = realloc(state->children, sizeof(kita_child_s) * state->num_children); // TODO error checking
	state->children[current] = (kita_child_s) { 0 };

	// Copy the command over
	state->children[current].cmd = strdup(cmd);

	// Create input/output streams as requested
	state->children[current].io[KITA_IOS_IN]  = in ?  
		libkita_stream_init(KITA_IOS_IN,  KITA_BUF_LINE) : NULL;
	state->children[current].io[KITA_IOS_OUT] = out ? 
		libkita_stream_init(KITA_IOS_OUT, KITA_BUF_LINE) : NULL;
	state->children[current].io[KITA_IOS_ERR] = err ? 
		libkita_stream_init(KITA_IOS_ERR, KITA_BUF_LINE) : NULL;
	
	return &state->children[current];

	/*
	kita_child_s child = { 0 };
	child.cmd = cmd;

	child.io[KITA_IOS_IN]  = in ?  libkita_stream_init(KITA_IOS_IN,  KITA_BUF_LINE) : NULL;
	child.io[KITA_IOS_OUT] = out ? libkita_stream_init(KITA_IOS_OUT, KITA_BUF_LINE) : NULL;
	child.io[KITA_IOS_ERR] = err ? libkita_stream_init(KITA_IOS_ERR, KITA_BUF_LINE) : NULL;

	return child;
	*/
}

void libkita_reap(kita_state_s *state)
{
	// waitpid() with WNOHANG will return...
	//  - PID of the child that has changed state, if any
	//  -  0  if there are relevan children, but none have changed state
	//  - -1  on error
	
	pid_t pid = 0;
	while ((pid = waitpid(-1, NULL, WNOHANG)) > 0)
	{
		kita_child_s *child = NULL;
		for (size_t i = 0; i < state->num_children; ++i)
		{	
			child = &state->children[i];

			if (child->pid == pid)
			{
				fprintf(stderr, "reaping child, PID %d\n", pid);
				kita_child_close(child);
				child->pid = 0;
				// TODO dispatch reap event
			}
		}
	}
}

void libkita_dispatch_event(kita_state_s *state, kita_event_s *event)
{

}

int libkita_handle_event(kita_state_s *state, struct epoll_event *epev)
{
	kita_event_s event = { 0 };
	event.child = (kita_child_s *) epev->data.ptr;
	
	// We've got data coming in
	if(epev->events & EPOLLIN)
	{
		// TODO
		fprintf(stdout, "kita event: EPOLLIN\n");
		// TODO how do we know if this occured on STDOUT or STDIN?
		state->cbs.child_stdout_data(state, &event);
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
	
	// No events have occured
	if (num_events == 0)
	{
		return 0;
	}
	
	// Wait for children that died, if any
	// TODO - shouldn't this come AFTER libkita_handle_event()?
	//        otherwise we might get the "child_died" event before
	//        the last output of said child
	libkita_reap(s);

	return libkita_handle_event(s, &epev);
}

// TODO - int or void?
//      - we need some more condition as to when we quit the loop?
int kita_loop(kita_state_s *s)
{
	while (kita_tick(s, 1000) == 0)
	{
		fprintf(stdout, "tick... tock...\n");
		// Nothing to do here
	}
	return 0; // TODO
}

int libkita_init_epoll(kita_state_s *state)
{
	int epfd = epoll_create(1);
	if (epfd < 0)
	{
		return -1;
	}
	state->epfd = epfd;
	return 0;
}

kita_state_s *kita_init()
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

kita_calls_s *kita_get_callbacks(kita_state_s *state)
{
	return &state->cbs;
}

void on_child_dead(kita_state_s *state, kita_event_s *event)
{
	fprintf(stdout, "on_child_dead()\n");
}

void on_child_data(kita_state_s *state, kita_event_s *event)
{
	fprintf(stdout, "on_child_data()\n");
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

	kita_child_s *block_datetime = kita_child_make(state, "~/.local/bin/candies/datetime", 0, 1, 0);
	kita_child_open(state, block_datetime);
	kita_loop(state);

	return EXIT_SUCCESS;
}

