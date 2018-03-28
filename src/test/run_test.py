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
import signal
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
                # proc.terminate()
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
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
                # proc.kill()
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        timer.cancel()
        sys.exit(1)

def start_procs(exes, in_shell = False):
    def create_subproc4(exe, fin, fout, ferr):
        subproc = subprocess.Popen(exe, stdin = fin, stdout = fout, stderr = ferr, shell = in_shell, preexec_fn = os.setsid) 
        return subproc

    procs = []
    for (index, (exe, i, o, e)) in enumerate(exes):
        print "Create proc %d with arguments %s." % (index, exe)
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

def test_multi():
    print "test fork"
    r = (["./bin/multi_recv"], None, open("r.log", "w"), open("r1.log", "w"))
    s1 = (["./bin/send"], subprocess.PIPE, open("s_1.log", "w"), open("s1_1.log", "w"))
    s2 = (["./bin/send"], subprocess.PIPE, open("s_2.log", "w"), open("s1_2.log", "w"))
    s3 = (["./bin/send"], subprocess.PIPE, open("s_3.log", "w"), open("s1_3.log", "w"))
    procs = start_procs([r, s1], True) # Must in shell, otherwise cause strange block
    
    time.sleep(1) # wait till connection is established
    print "start a new sender"
    procs.extend(start_procs([s2], True)) # start a new sender
    procs[1].stdin.write("message from sender 1\n")
    procs[2].stdin.write("message from sender 2\n")
    print "close the listening socket sender1"
    procs[1].stdin.close()
    print "start another sender"
    procs.extend(start_procs([s3], True)) # start a new sender
    procs[3].stdin.write("message from sender 3\n")
    print "close all senders"
    procs[2].stdin.close()
    procs[3].stdin.close()
    wait_procs(procs, 10.0)


def test_normal():
    print "test poll and urg"
    r = (["./bin/recvfile", "-oout.dat"], subprocess.PIPE, open("r.log", "w"), open("r1.log", "w"))
    s = (["./bin/sendfile_poll", "-iin.dat", "-d0", "-l0"], subprocess.PIPE, open("s.log", "w"), open("s1.log", "w"))
    procs = start_procs([r, s])
    def callback_urg():
        time.sleep(1) # wait till connection is established
        print "start sending URG messages"
        procs[1].stdin.write("urg msg start\n")
        procs[1].stdin.write("Hello, world!\n")
        time.sleep(1)
        procs[1].stdin.write("urg msg end\n")
        procs[1].stdin.close()
        print "end sending URG messages"
    t = Thread(target=callback_urg)
    t.start()
    wait_procs(procs, 20.0)
    t.join()

    print "test normal"
    test_once4(["./bin/sendfile"], ["./bin/recvfile"], "in.dat", "out.dat", 20.0)

    print "test clock drift"
    r = (["./bin/recv -s"], None, open("r.log", "w"), open("r1.log", "w"))
    s = (["./bin/send -s"], subprocess.PIPE, open("s.log", "w"), open("s1.log", "w"))
    procs = start_procs([r, s], True) # Must in shell, otherwise cause strange block
    def callback_drift():
        time.sleep(1) # wait till connection is established
        print "start sending simulated packets"
        procs[1].stdin.write("s0 a0 i0 o0 fA w65535 p9876\n")
        # test packet with an option
        # procs[1].stdin.write("s0 a0 i0 o0 fA w65535 p9876 O{ATP_OPT_SOCKID 2 100}\n")
        procs[1].stdin.write("s0 a0 i0 o0 fA w65535 p9876 O{ATP_OPT_MSS 4 100}\n")
        # start clock drift probing
        procs[1].stdin.write(":S\n")
        print "end sending simulated packets"
        procs[1].stdin.close()

    t = Thread(target=callback_drift)
    t.start()
    wait_procs(procs, 10.0)
    t.join()


def test_invalid_conditions():
    print "test sending invalid packet"
    def callback_invalid():
        time.sleep(0.8)
        print "send simulated SYN packet to a non-exist socket."
        # In this case, recvfile is no longer listening to port 9876, so there will be a "Can't locate ... by fd" error in r1.log
        subprocess.call([os.getcwd() + '/bin/packet_sim', '-s0', '-a0', '-i113', '-o0', '-fS', '-w65535', '-p9876'], stdout=None)

        print "send simulated normal packet to a non-exist socket."
        # In this case, there's no socket which receives packet of port 9876 and sockid 113, so there will be a "Can't locate ... by packet head" error in r1.log
        subprocess.call([os.getcwd() + '/bin/packet_sim', '-s0', '-a0', '-i113', '-o0', '-f', '-w65535', '-p9876'], stdout=None) 

        # print "send simulated RST packet to an exist socket to recvfile by faking myself as sendfile."
        # subprocess.call([os.getcwd() + '/bin/packet_sim', '-s0', '-a0', '-i112', '-o0', '-fR', '-w65535', '-p9876', '-P4444'], stdout=None)   
        
    t = Thread(target=callback_invalid)
    t.start()
    test_once4(["./bin/sendfile", "-p9876", "-s111", "-P4444"], ["./bin/recvfile", "-p9876", "-s112"], "in.dat", "out.dat", 20.0)
    t.join()

    # print "test on a non-listening port"
    # In this case, recvfile will receive no UDP packet from sendfile
    test_once4(["./bin/sendfile", "-p9876"], ["./bin/recvfile", "-p9877"], "in.dat", "out.dat", 15.0)

def test_on_bad_network():
    print "test at 1000ms delay(connection may not be established)"
    test_once4(["./bin/sendfile", "-d1000"], ["./bin/recvfile", "-d1000"], "in.dat", "out.dat", 50.0)

    print "test at 50% loss rate"
    test_once4(["./bin/sendfile", "-l0.5"], ["./bin/recvfile", "-l0.5"], "in.dat", "out.dat", 130.0)

def main(): 
    test_multi()

    test_normal()

    test_on_bad_network()

    test_invalid_conditions()

    return

if __name__ == '__main__':
    main()
