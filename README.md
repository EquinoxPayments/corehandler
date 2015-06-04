# corehandler
## Summary
Generates a plain-text crash report with stack backtrace when a program
crashes. For Linux ARMv6 and ARMv7 systems.

## History
corehandler started off as a modification of
[crash_handler](http://elinux.org/Crash_handler) but all the code was
eventually replaced and new features added.

## Notable features
* Produces stack backtrace even for programs which have been stripped of
debugging information and do not contain exception-handling tables (e.g.
plain-C programs).
* Non-intrusive
  * doesn't have external dependencies;
  * completely transparent for programs: no need to link with any special
    libraries, modify environment variables or modify the source code;
  * runs only when it is actually needed.

