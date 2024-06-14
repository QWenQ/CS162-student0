# Redirection
if '>' occurs, replace `STDOUT_FILENO` with target file descriptor;
if '<' occurs, replace `STDIN_FILENO` with target file descriptor;

# Pipes

# Signal handling
## Task
1. ensure each subprocess is in its own process group;
2. stopping signals should only affect the foreground program, not the background shell;

## Implementation
### T1
1. child process calls `setpgrp()`;
2. parent process calls `setpgid(cpid, cpid)`;

### T2
1. when parent process shell is delivered a signal, forward the signal to all processes in the foreground group;
2. when a process in the foreground group recieves a signal, handle it as default;
3. after children exits, the parent reset all sigal disposition to default and back to the foreground process;

NOTE:
A child created via fork(2) inherits a copy of its parent's signal dispositions.
During an execve(2), the dispositions of handled signals are reset to the default; the dispositions of ignored  signals are left unchanged. 