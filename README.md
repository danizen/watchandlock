# watchandlock

Utility to simplify checking for lock-based errors in file-handling implementations for Windows

## Summary

Many programmers often assume a model of advisory locking due to familiarity with POSIX from Linux platforms.
However, Windows has OpLocks and specialized APIs for implementing security policies.  This module attempts to
provide a simple command-line to use dynamic API events and file locking to thow a wrench into such software
to help bullet proof it on Windows.

## Further reading

These pip issues orginated work to duplicate such an issue:

- https://github.com/aws/aws-cli/issues/2654
- https://github.com/pypa/pip/issues/7033
- https://github.com/pypa/pip/issues/7280

This blog entry provides the first technique tried to reproduce the issue:
- http://timgolden.me.uk/python/win32_how_do_i/watch_directory_for_changes.html
