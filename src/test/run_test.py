import os, sys
import subprocess
import time
import math, random
import multiprocessing
from threading import Thread, Timer
import threading
from Queue import Queue, Empty
from multiprocessing.dummy import Pool as ThreadPool

# Here are first 3 test prototypes https://paste.ubuntu.com/26488236/

def test_once4(exe_send, exe_recv, input_fn, output_fn, timeout):

    def create_subproc4(exe, fout, ferr):
        subproc = subprocess.Popen(exe, stdout = fout, stderr = ferr) 
        return subproc

    proc_recv = create_subproc4(exe_recv + ["-o" + output_fn], open("r.log", "w"), open("r1.log", "w"))
    proc_send = create_subproc4(exe_send + ["-i" + input_fn], open("s.log", "w"), open("s1.log", "w"))

    procs = [proc_recv, proc_send]
    proc_size = len(procs)
    done_list = [False] * proc_size
    done_size = 0

    def kill_proc():
        for (i, proc) in zip(range(proc_size), procs):
            if proc.poll() == None:
                print "Kill proc %d." % (i)
                proc.terminate()
    timer = Timer(timeout, kill_proc)
    timer.start()

    while True:
        for (i, proc) in zip(range(proc_size), procs):
            if (not done_list[i]) and proc.poll() != None:
                # if this proc is finished
                done_size += 1
                done_list[i] = True
                print "Proc %d finished." % (i)
        if done_size == proc_size:
            break
        time.sleep(0.1)

    # necessary, otherwise the process will sleep until timer triggered
    timer.cancel()

    try:
        print "in size {}".format(os.path.getsize(input_fn))
        print "out size {}".format(os.path.getsize(output_fn))
        return
    except OSError:
        pass

def main():
    print "test normal"
    test_once4(["./bin/sendfile"], ["./bin/recvfile"], "in.dat", "out.dat", 25.0)
    print "test error"
    test_once4(["./bin/sendfile", "-p 9876"], ["./bin/recvfile", "-p 9877"], "in.dat", "out.dat", 15.0)
    print "test at 50% loss rate"
    test_once4(["./bin/sendfile", "-l"], ["./bin/recvfile", "-l"], "in.dat", "out.dat", 130.0)
    return

if __name__ == '__main__':
    main()