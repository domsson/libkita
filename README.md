# libkita

> This is an early work in progress. Hardly anything works or is implemented (correctly).

libkita is a small library that makes it easy to create and run child processes, monitor their activity, read their `stdout` and `stderr` output, as well as write to their `stdin`. It is not a _one size fits all_ library; I'm writing this for a particular use-case and the library therefore makes certain assumptions and is lacking a lot of options and features that I don't need for my purposes.  

## Development notes / concept

The idea is to have a library that can be used in two ways:

- Have kita keep track of all children and get informed of events via callbacks
- Use kita functions to create and manage children, but keep track of them yourself

