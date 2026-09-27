"""Test suite package.

Every module here runs the real CLI, in-process and as a subprocess. Those runs mirror result.txt to
the shared evidence mount, which is the operator's directory and not the suite's to write to: a full
run left forty files there, and no assertion noticed because nothing owned that directory.

Setting the override before autorecon_v8 is imported covers both cases, since subprocesses inherit
the environment. /dev/shm is a real tmpfs mount, so the guard's mount check is still genuinely
exercised rather than stubbed out.
"""
import atexit
import os
import shutil

os.environ["AUTORECON_KALI_SHARE"] = "/dev/shm"

# Not every module that runs the CLI registers a cleanup, so /dev/shm collected mirrors from suites
# that had no reason to think about the share at all. One exit hook covers all of them.
atexit.register(shutil.rmtree, "/dev/shm/autorecon-results", True)
