import os, sys
import subprocess
import time
import math, random
import time
import multiprocessing
from threading import Thread, Timer
import threading
from Queue import Queue, Empty
from multiprocessing.dummy import Pool as ThreadPool

def create_subproc(exe, callback, timeout):
    subproc = subprocess.Popen(exe, stdout = subprocess.PIPE, stderr = subprocess.PIPE
        , bufsize=1, close_fds='posix' in sys.builtin_module_names) 
    t = Thread(target=callback, args=(subproc, ))
    t.daemon = True
    def kill_proc():
        if subproc.poll() == None:
            # terminate signal is handled by `exit(0)`, otherwise ".gcna" will not be generated
            subproc.terminate()
    timer = Timer(timeout, kill_proc)
    return (subproc, t, timer)

def test_once(exe_send, exe_recv, timeout):
    def callback_send(subproc):
        f = open("s.log", "w")
        f2 = open("s1.log", "w")
        while True:
            line = subproc.stdout.readline()
            if line:
                print>>f, line,
            line2 = subproc.stderr.readline()
            if line2:
                print>>f2, line2,
            if subproc.poll() != None:
                print>>f, "Finished with", subproc.poll()
                f.close()
                f2.close()
                break
    def callback_recv(subproc):
        f = open("r.log", "w")
        f2 = open("r1.log", "w")
        while True:
            line = subproc.stdout.readline()
            if line:
                print>>f, line,
            line2 = subproc.stderr.readline()
            if line2:
                print>>f2, line2,
            if subproc.poll() != None:
                print>>f, "Finished with", subproc.poll()
                f.close()
                f2.close()
                break

    # Setting timeout is important because currently we have no keepalive timer
    # If sender timout and exit, then receiver will no longer get any message from sender,
    # However, due to our design, receiver will not send any message except from SYN/FIN/ACK,
    # and it'll never know peer is dead. So we add timeout to "recvfile" to make sure it will terminate.
    (proc_recv, t_recv, tmr_recv) = create_subproc(exe_recv, callback_recv, timeout)
    (proc_send, t_send, tmr_send) = create_subproc(exe_send, callback_send, timeout)

    procs = [proc_recv, proc_send]
    ths = [t_recv, t_send]
    tmrs = [tmr_recv, tmr_send]
    proc_size = len(procs)

    for i in xrange(proc_size):
        ths[i].start()
    for i in xrange(proc_size):
        tmrs[i].start()
    for i in xrange(proc_size):
        ths[i].join()

    for proc in procs:
        if proc.poll() == None:
            print "Killed"
            proc.kill()

def main():
    print "test normal"
    test_once(["./bin/sendfile"], ["./bin/recvfile"], 30.0)
    print "test at 50%% loss"
    test_once(["./bin/sendfile", "-l"], ["./bin/recvfile", "-l"], 150.0)

if __name__ == '__main__':
    main()