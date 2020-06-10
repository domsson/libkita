# libkita

_This is a work in progress. Some things are not implemented. Other things might break._

libkita makes it easy to create and run child processes, monitor their activity, read their `stdout` and `stderr` output, as well as write to their `stdin`. It is not a _one size fits all_ library; I'm writing this for a [particular use-case](https://github.com/domsson/succade) and the library therefore makes certain assumptions and is lacking features that I don't need for my purposes.

# Installation

First, build the library. There are two build scripts, for shared and static respectively. Let's go with shared:

    chmod +x build-shared
    ./build-shared

The actual installation is dependent on your distribution, but usually means you'll have to copy the `.h` and the compiled `.so` to some system folder, then run a command to have the system re-load all libraries. For my Debian system, this does the trick:

    cp ./lib/libkita.h /usr/include/
    cp ./lib/libkita.so /usr/lib/x86_64-linux-gnu/
    ldconfig -v -n /usr/lib

Alternatively, you could just put all source files into your project and compile them alongside your own code.

# Usage

There will be more detailed documentation in the GitHub Wiki soon. Until then, see this simple example for an idea of how to use kita:

    // Get a kita state struct
    kita_state_s *kita = kita_init();

    // Set callbacks, so we get informed of child events
    kita_set_callback(kita, KITA_EVT_CHILD_READOK, on_child_readok);
    kita_set_callback(kita, KITA_EVT_CHILD_CLOSED, on_child_closed);

    // Get a kita child struct that will run the `date` command
    char *cmd = "date +'%H:%M:%S'";
    kita_child_s *child = kita_child_new(cmd, 0, 1, 0);

    // Add the child to the kita state
    kita_child_add(kita, child);

    // Loop until some error or signal happens
    kita_loop(kita);

A callback function could look like this:

    void on_child_readok(kita_state_s *ks, kita_event_s *ke)
    {
        // Read the data from the child
        char *output = kita_child_read(ke->child, ke->ios);

        // Print the data
        fprintf(stdout, "%s\n", output);

        // Free the data
        free(output);
    } 

