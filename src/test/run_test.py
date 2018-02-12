# *   Calvin Neo
# *   Copyright (C) 2017  Calvin Neo <calvinneo@calvinneo.com>
# *   https://github.com/CalvinNeo/ATP
# *
# *   This program is free software; you can redistribute it and/or modify
# *   it under the terms of the GNU General Public License as published by
# *   the Free Software Foundation; either version 2 of the License, or
# *   (at your option) any later version.
# *
# *   This program is distributed in the hope that it will be useful,
# *   but WITHOUT ANY WARRANTY; without even the implied warranty of
# *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# *   GNU General Public License for more details.
# *
# *   You should have received a copy of the GNU General Public License along
# *   with this program; if not, write to the Free Software Foundation, Inc.,
# *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

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

def wait_procs(procs, timeout):
    proc_size = len(procs)
    done_list = [False] * proc_size
    done_size = 0
    def kill_proc():
        for (i, proc) in enumerate(procs):
            if proc.poll() == None:
                print "Kill proc %d %s." % (i, str(proc.pid))
                proc.terminate()
    timer = Timer(timeout, kill_proc)
    timer.start()

    try:
        while True:
            for (i, proc) in enumerate(procs):
                if (not done_list[i]) and proc.poll() != None:
                    # if this proc is finished
                    done_size += 1
                    done_list[i] = True
                    print "Proc %d %s finished." % (i, str(proc.pid))
            if done_size == proc_size:
                break
            time.sleep(0.1)

        # necessary, otherwise the process will sleep until timer triggered
        timer.cancel()

    except KeyboardInterrupt:
        print "Quit by Ctrl+C"
        for proc in procs:
            if proc.poll() == None:
                proc.kill()
        timer.cancel()
        sys.exit(1)

def start_procs(exes):
    def create_subproc4(exe, fin, fout, ferr):
        subproc = subprocess.Popen(exe, stdin = fin, stdout = fout, stderr = ferr) 
        return subproc

    procs = []
    for (index, (exe, i, o, e)) in enumerate(exes):
        print "Create proc %d %s." % (index, exe)
        procs.append(create_subproc4(exe, i, o, e))
        time.sleep(0.5)
    return procs

def test_once4(exe_send, exe_recv, input_fn, output_fn, timeout):
    exe_recv = (exe_recv + ["-o" + output_fn], None, open("r.log", "w"), open("r1.log", "w"))
    exe_send = (exe_send + ["-i" + input_fn], None, open("s.log", "w"), open("s1.log", "w"))

    procs = start_procs([exe_recv, exe_send])
    wait_procs(procs, timeout)

    try:
        print "in size {}".format(os.path.getsize(input_fn))
        print "out size {}".format(os.path.getsize(output_fn))
        return
    except OSError:
        pass

def main():

    # subproc = subprocess.Popen(["./bin/sendfile_test"], stdin = subprocess.PIPE, stdout = None, stderr = None) 
    # def callback_urg():
    #     time.sleep(1)
    #     # subproc.communicate("1\n")
    #     # subproc.stdin.write("1\n")
    #     subproc.stdin.close()
    # t = Thread(target=callback_urg)
    # t.start()
    # subproc.wait()
    # t.join()

    print "test poll and urg"
    r = (["./bin/recvfile", "-oout.dat"], subprocess.PIPE, open("r.log", "w"), open("r1.log", "w"))
    s = (["./bin/sendfile_poll", "-iin.dat"], subprocess.PIPE, open("s.log", "w"), open("s1.log", "w"))
    procs = start_procs([r, s])
    def callback_urg():
        time.sleep(3)
        print "start sending URG messages"
        procs[1].stdin.write("urg msg start\n")
        time.sleep(1)
        procs[1].stdin.close()
        print "end sending URG messages"
    t = Thread(target=callback_urg)
    t.start()
    wait_procs(procs, 20.0)
    t.join()

    print "test at 1000ms delay(connection may not be established)"
    test_once4(["./bin/sendfile", "-d1000"], ["./bin/recvfile", "-d1000"], "in.dat", "out.dat", 130.0)

    # print "test at 200ms delay"
    # test_once4(["./bin/sendfile", "-d"], ["./bin/recvfile", "-d"], "in.dat", "out.dat", 130.0)

    print "test_fragmentation"

    print "test_port_multiplexing"

    print "test invalid packet"
    def callback_invalid():
        time.sleep(3)
        print "send simulated SYN packet to a non-exist socket."
        subprocess.call([os.getcwd() + '/bin/packet_sim', '-s0', '-a0', '-i113', '-o0', '-fS', '-w65535', '-p9876'], stdout=None)  
        print "send simulated normal packet to a non-exist socket."
        subprocess.call([os.getcwd() + '/bin/packet_sim', '-s0', '-a0', '-i113', '-o0', '-f', '-w65535', '-p9876'], stdout=None) 

        # print "send simulated RST packet to an exist socket to recvfile by faking myself as sendfile."
        # subprocess.call([os.getcwd() + '/bin/packet_sim', '-s0', '-a0', '-i112', '-o0', '-fR', '-w65535', '-p9876', '-P4444'], stdout=None)   
        
    t = Thread(target=callback_invalid)
    t.start()
    test_once4(["./bin/sendfile", "-p9876", "-s111", "-P4444"], ["./bin/recvfile", "-p9876", "-s112"], "in.dat", "out.dat", 20.0)
    t.join()
    
    print "test normal"
    test_once4(["./bin/sendfile"], ["./bin/recvfile"], "in.dat", "out.dat", 20.0)

    print "test different port"
    test_once4(["./bin/sendfile", "-p9876"], ["./bin/recvfile", "-p9877"], "in.dat", "out.dat", 15.0)

    print "test at 50% loss rate"
    test_once4(["./bin/sendfile", "-l0.5"], ["./bin/recvfile", "-l0.5"], "in.dat", "out.dat", 130.0)
    
    return

if __name__ == '__main__':
    main()
