#!/usr/bin/python
import logging
import os
import platform
import re
import sys
import tempfile
import time
from argparse import ArgumentParser, ArgumentError

if not platform.platform().startswith('Windows'):
    raise RuntimeError('This software only supports Windows')

from filelock import FileLock, Timeout
import win32file
import win32con

LOG = logging.getLogger('watchandlock')

ACTIONS = {
    1: "Created",
    2: "Deleted",
    3: "Updated",
    4: "Renamed from something",
    5: "Renamed to something"
}


FILE_LIST_DIRECTORY = 0x0001


def directory_path_type(value):
    if not os.path.isdir(value):
        raise ArgumentError('Must be the path to an existing directory')
    return os.path.abspath(value)


def regexpr_type(value):
    try:
        expr = re.compile(value)
    except re.error:
        raise ArgumentError('Must be a valid regular expression')
    return expr


def non_negative_float_type(value):
    try:
        value = float(value)
        if value < 0:
            raise ArgumentError('Must be a non-negative floating point value')
        if value == 0.0:
            value = sys.float_info.max
    except ValueError:
        raise ArgumentError('Must be a non-negative floating point value')
    return value



def create_parser(prog_name):
    parser = ArgumentParser(prog=prog_name, description='Watch for new files or directories in a path')
    parser.add_argument('path', metavar='PATH', default=tempfile.gettempdir(),
                        type=directory_path_type, help='The path to the directory to scan')
    parser.add_argument('--pattern', metavar='EXPR', default='confsecrets.*', type=regexpr_type,
                        help='Specify a file pattern to which to react')
    parser.add_argument('--action', default='open', choices=['open', 'lock', 'logonly'],
                        help='What to do with the file')
    parser.add_argument('--timeout', metavar='SECONDS', default='5.0', type=non_negative_float_type,
                        help='How long to wait for a matching file to be locked/opened')
    parser.add_argument('--delay', metavar='SECONDS', default='300.0', type=non_negative_float_type,
                        help='How long to hold the lock/hold the file open')
    parser.add_argument('--verbose', '-v', default=False, action='store_true',
                        help='Turn on debug logging')
    return parser


def log_only(path, action_name, timeout=5.0, delay=2.0):
    """
    Do nothing, accept the path, timeout, and delay as arguements
    """
    LOG.info('%s %s', file, action_name)


def open_and_wait(path, action_name, timeout=5.0, delay=2.0):
    """
    open the file, and read again and again in 4k increments until the deadline
    """
    LOG.info('%s %s: opening and reading for %0.1f seconds', path, action_name, delay)
    try:
        deadline = time.time() + delay
        with open(path, 'rb') as f:
            while time.time() < deadline:
                buf = f.read(4096)
                if len(buf) == 0:
                    f.seek(0, os.SEEK_SET)
    except OSError as e:
        LOG.warning('%s: error opening or reading file', exc_info=e)
    LOG.info('%s: closed', path)


def sysopen_and_wait(path, action_name, timeout=5.0, delay=2.0):
    """
    Open the file using windows System APIs and set file disposition so that it may be deleted.
    """
    LOG.info('%s %s: opening (internals) and waiting for %0.1f seconds', path, action_name, delay)
    hFile = None
    try:
        # Open/Create directory with Windows Base APIs
        hFile = win32file.CreateFile(
            path,
            win32con.GENERIC_READ,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_BACKUP_SEMANTICS,
            None
        )

    finally:
        if hFile is not None:
            win32file.CloseHandle(hFile)



def lock_and_wait(path, action_name, timeout=5.0, delay=2.0):
    """
    lock the file, and wait for delay seconds
    """
    LOG.info('%s %s: locking and waiting %0.1f seconds', path, action_name, delay)
    lock = FileLock(path, timeout=timeout)
    with lock:
        time.sleep(delay)
    LOG.info('%s: unlocked', path)


MY_ACTIONS = {
    'open': open_and_wait,
    'sysopen': sysopen_and_wait,
    'lock': lock_and_wait,
    'logonly': log_only,
}



def watch_and_take_action(path_to_watch, pattern, action='logonly', timeout=5.0, delay=1.0):
    """
    Use an event model to watch a particular directory for a pattern.
    On a match of the pattern, take some action on the file which can be observed.
    """
    myaction = MY_ACTIONS.get(action, None)
    if not myaction:
        raise ValueError("action must be one of 'open', 'lock', or 'logonly'")

    # Open/Create directory with Windows Base APIs
    hDir = win32file.CreateFile(
        path_to_watch,
        FILE_LIST_DIRECTORY,
        win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
        None,
        win32con.OPEN_EXISTING,
        win32con.FILE_FLAG_BACKUP_SEMANTICS,
        None
    )

    while 1:
        #
        # At time of writing, documentation may be found at:
        # https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw
        #
        # win32file performs wrapping of this to make it a bit easier.
        #
        # ReadDirectoryChangesW takes a previously-created
        # handle to a directory, a buffer size for results,
        # a flag to indicate whether to watch subtrees and
        # a filter of what changes to notify.
        #
        # NB Tim Juchcinski reports that he needed to up
        # the buffer size to be sure of picking up all
        # events when a large number of files were
        # deleted at once.
        #
        results = win32file.ReadDirectoryChangesW (
            hDir,
            1024,       # Size of buffer
            True,       # watch subtree
            (win32con.FILE_NOTIFY_CHANGE_FILE_NAME | 
             win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
             win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES | 
             win32con.FILE_NOTIFY_CHANGE_SIZE |
             win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
             win32con.FILE_NOTIFY_CHANGE_SECURITY),
            None,
            None
        )
        for action, file in results:
            full_filename = os.path.join(path_to_watch, file)
            action_name = ACTIONS.get(action, 'Unknown')
            LOG.debug('%s - %s', full_filename, action_name)
            m = pattern.match(os.path.basename(file))
            if m and action == 1:
                myaction(full_filename, action_name, timeout, delay)


def main_guts(prog_name, args):
    parser = create_parser(prog_name)
    opts = parser.parse_args(args)

    loglevel = logging.DEBUG if opts.verbose else logging.INFO
    handler = logging.StreamHandler()
    handler.setLevel(loglevel)
    handler.setFormatter(logging.Formatter('[%(levelname)s] %(name)s: %(message)s'))
    LOG.addHandler(handler)
    LOG.setLevel(loglevel)
    LOG.debug('arguments %r', opts)
    LOG.info('this software uses Windows blocking APIs: use Ctrl+Break to terminate')

    watch_and_take_action(opts.path, opts.pattern, opts.action, opts.timeout, opts.delay)


def main(prog_name=None, args=None):
    return main_guts(sys.argv[0], sys.argv[1:])


if __name__ == '__main__':
    main()
