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

/*
 * Sets the global SIGCHLD indicator.
 */
void sigchld_handler(int sig)
{
	sigchld = 1;
}

/*
 * Sets the global SIGPIPE indicator.
 */
void sigpipe_handler(int sig)
{
	sigpipe = 1;
}

/*
 * Set the given file pointer to be line buffered.
 * Returns 0 on success, -1 on error.
 */
int fp_linebuffered(FILE *fp)
{
	if (fp == NULL)
	{
		return -1;
	}

	setlinebuf(fp);
	return 0;
}

/*
 * Set the file descriptor for the given file pointer to be non-blocking.
 * Returns 0 on success, -1 on error.
 */
int fp_nonblocking(FILE *fp)
{
	if (fp == NULL)
	{
		return -1;
	}

	int fd = fileno(fp);
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1)
	{
		return -1;
	}
	flags |= O_NONBLOCK;
	return fcntl(fd, F_SETFL, flags);
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

// TODO would be nice if we didn't have to hand in `in`, `out` and `err`
int kita_open_child(kita_child_s *child, int in, int out, int err)
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
	
	fprintf(stderr, "open_child(): %s\n", cmd ? cmd : child->cmd);

	// Execute the block and retrieve its PID
	child->pid = popen_noshell(
			cmd ? cmd : child->cmd, 
			in  ? &(child->fp[KITA_STDIN])  : NULL,
			out ? &(child->fp[KITA_STDOUT]) : NULL,
		        err ? &(child->fp[KITA_STDERR]) : NULL);
	free(cmd);

	// Check if that worked
	if (child->pid == -1)
	{
		// popen_noshell() failed to open it
		return -1;
	}
	
	// TODO do we really ALWAYS want linebuf for ALL THREE streams?
	fp_linebuffered(child->fp[KITA_STDIN]);
	fp_linebuffered(child->fp[KITA_STDOUT]);
	fp_linebuffered(child->fp[KITA_STDERR]);

	// Remember the time of this invocation
	child->last_open = get_time();
	return 0;
}

/*
 * Close the child's file pointers via fclose(), then set them to NULL.
 */
void kita_close_child(kita_child_s *child)
{
	if (child->fp[KITA_STDIN] != NULL)
	{
		fclose(child->fp[KITA_STDIN]);
		child->fp[KITA_STDIN] = NULL;
	}
	if (child->fp[KITA_STDOUT] != NULL)
	{
		fclose(child->fp[KITA_STDOUT]);
		child->fp[KITA_STDOUT] = NULL;
	}
	if (child->fp[KITA_STDERR] != NULL)
	{
		fclose(child->fp[KITA_STDERR]);
		child->fp[KITA_STDERR] = NULL;
	}
}

int kita_kill_child(kita_child_s *child)
{
	if (child->pid > 1)
	{
		// SIGTERM can be caught (and even ignored), it allows 
		// the child to do clean-up; SIGKILL would be immediate
		return kill(child->pid, SIGTERM);

		// We do not set the child's PID to 0 here, because the 
		// child might not immediately terminate (clean-up, etc). 
		// Instead, we should catch SIGCHLD, then use waitpid()
		// to determine the termination and to set PID to 0.
	}
	return -1;
}

/*
 * Attempt to read from the child's stdout file pointer, and store the result, 
 * if any, in the child's `output` field.
 */
int read_child(kita_child_s *child, size_t len)
{
	// Can't read from child if its `stdout` is dead
	if (child->fp[KITA_STDOUT] == NULL)
	{
		//fprintf(stderr, "read_child(): stdout dead: `%s`\n", child->cmd);
		return -1;
	}
	
	// TODO maybe use getline() instead? It allocates a suitable buffer!
	char *buf = malloc(len);

	// TODO we need to figure out if all use-cases are okay with just 
	//      calling fgets() once; at least one use-case was using the
	//      while-loop approach; not sure if that might now break?
	//      In particular, isn't it bad if we don't consume all the 
	//      data that is available for read? But the issue is that if
	//      we use the while approach with live blocks or sparks, then 
	//      the while will keep on looping forever...

	/*
	size_t num_lines = 0;
	while (fgets(buf, len, child->fp[KITA_STDOUT]) != NULL)
	{
		++num_lines;
	}

	if (num_lines == 0)
	*/

	if (fgets(buf, len, child->fp[KITA_STDOUT]) == NULL)
	{
		fprintf(stderr, "read_child(): fgets() failed: `%s`\n", child->cmd);
		if (feof(child->fp[KITA_STDOUT]))
		{
			fprintf(stderr, "\t(EOF - nothing to read)\n");
		}
		if (ferror(child->fp[KITA_STDOUT]))
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
			clearerr(child->fp[KITA_STDOUT]);
		}
		return -1;
	}

	/*
	if (child->output)
	{
		free(child->output);
		child->output = NULL;
	}

	buf[strcspn(buf, "\n")] = 0; // Remove '\n'
	child->output = buf; // Copy pointer to result over
	*/

	child->last_read = get_time();
	return 0;
}

int feed_child(kita_child_s *child, const char *input)
{
	/*
	// Child has no open stdin file pointer
	if (child->fp[KITA_STDIN] == NULL)
	{
		return -1;
	}

	// No input given, or input is empty 
	if (empty(input))
	{
		return -1;
	}

	return fputs(input, child->fp[KITA_STDIN]);
	*/
	return -1;
}

/*
 * TODO We could theoretically use this function to register events that aren't 
 *      part of the state's event array, as we don't perform any checks in this 
 *      regard -- what can/should we do about this?
 */
int register_event(kita_state_s *state, kita_event_s *ev)
{
	/*
	if (ev == NULL)
	{
		return -1;
	}

	if (ev->fd < 0)
	{
		return -1;
	}

	struct epoll_event eev = { 0 };
	eev.data.ptr = ev;
	eev.events = (ev->fd_type == KITA_STDIN ? EPOLLOUT : EPOLLIN) | EPOLLET;

	if (epoll_ctl(state->epfd, EPOLL_CTL_ADD, ev->fd, &eev) == 0)
	{
		// Success
		ev->registered = 1;
		return 0;
	}
	if (errno == EEXIST)
	{
		// fd was already registered!
		ev->registered = 1;
	}
	// Some other error
	return -1;
	*/
	return -1;
}

int libkita_child_del_event(kita_state_s *state, kita_child_s *child)
{
	// TODO stdin, stdout, stderr
	return epoll_ctl(state->epfd, EPOLL_CTL_DEL, fileno(child->fp[KITA_STDIN]), NULL);
}

int libkita_child_reg_event(kita_state_s *state, kita_child_s *child)
{
	struct epoll_event ev = { 0 };
	ev.data.ptr = (void *) child;
	// TODO stdin, stdout, stderr
	ev.events = KITA_STDIN | EPOLLET;

	// TODO stdin, stdout, stderr
	return epoll_ctl(state->epfd, EPOLL_CTL_ADD, fileno(child->fp[KITA_STDIN]), &ev);
}

kita_child_s *kita_child_add(kita_state_s *state, kita_child_s *child)
{
	// array index for the new child
	int current = state->num_children;

	// increase array size and add new child
	state->num_children += 1;
	state->children = realloc(state->children, state->num_children);
	state->children[current] = *child;
	
	// register the child with epoll
	libkita_child_reg_event(state, child);

	return &state->children[current];
}

void libkita_reap(kita_state_s *state)
{
	pid_t pid = 0;
	while((pid = waitpid(-1, NULL, WNOHANG)))
	{
		kita_child_s *child = NULL;
		for (size_t i = 0; i < state->num_children; ++i)
		{	
			child = &state->children[i];

			if (child->pid == pid)
			{
				fprintf(stderr, "reaping child, PID %d\n", pid);
				kita_close_child(child);
				child->pid = 0;
			}
		}
	}
}

int libkita_handle_event(kita_state_s *s, struct epoll_event *epev)
{
	// We've got data coming in
	if(epev->events & EPOLLIN)
	{
		// TODO
		fprintf(stdout, "kita event: EPOLLIN\n");
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
	// Check if we have received SIGCHLD
	/*
	if (sigchld)
	{
		reap_children(&state);
		sigchld = 0;
	}
	*/
	libkita_reap(s);

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

	return libkita_handle_event(s, &epev);
}

// TODO - int or void?
//      - we need some more condition as to when we quit the loop?
int kita_loop(kita_state_s *s)
{
	while (kita_tick(s, -1) == 0)
	{
		// Nothing to do here
	}
	return 0; // TODO
}

int libkita_init_signals(kita_state_s *s)
{
	// SIGCHLD tells us that a child process has ended
	struct sigaction sa_chld = {
		.sa_handler = &sigchld_handler
	};

	// TODO (using this for testing, for now)
	// Not sure if we need to care about SIGPIPE
	// https://stackoverflow.com/a/18963142/
	// TODO actually, we might want to do this instead:
	// https://stackoverflow.com/a/450130/
	struct sigaction sa_pipe = {
		.sa_handler = &sigpipe_handler
	};

	int success = 0;
        success += sigaction(SIGCHLD, &sa_chld, NULL);
	success += sigaction(SIGPIPE, &sa_pipe, NULL);

	return success;
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

	// Register the relevant signal handlers
	/*
	if (libkita_init_signals(s) != 0)
	{
		return NULL;
	}
	*/

	// Initialize an epoll instance
	if (libkita_init_epoll(s) != 0)
	{
		return NULL;
	}

	// Return a pointer to the created state struct
	return s;
}

int main(int argc, char **argv)
{
	kita_state_s *state = kita_init();

	if (state == NULL)
	{
		return EXIT_FAILURE;
	}

	kita_loop(state);

	return EXIT_SUCCESS;
}

