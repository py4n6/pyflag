#!/usr/bin/env python
# ******************************************************
# Copyright 2006
# Michael Cohen <scudette@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.87-pre1 Date: Thu Jun 12 00:48:38 EST 2008$
# ******************************************************
#
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# ******************************************************

""" A distributed processing framework for PyFlag.

The distributed framework has been overhauled from previous versions.

Requirements
------------

Our requirements from a distributed processing framework are:

1. We must be able to schedule jobs from any worker.

2. All workers are capable of servicing jobs from any other worker.

3. Workers can be run from a Nanny. If the worker exits the nanny restarts another worker.

4. Workers must be able to exist when their nanny or master exits.


""" 
import sys,os,select, pytdb
import pyflag.conf
config=pyflag.conf.ConfObject()
import pyflag.pyflaglog as pyflaglog
import atexit,os,signal,time
import pyflag.DB as DB
import pyflag.Registry as Registry
import pyflag.Store as Store
import pdb
import pyflag.FlagFramework as FlagFramework
import pickle

## All writes to the pipes must be exactly this size. This guarantees
## that commands are atomically read and written.
PACKET_SIZE = 512
job_pipe = None
job_tdb = None

config.add_option("MAXIMUM_WORKER_MEMORY", default=0, type='int',
                  help='Maximum amount of memory (Mb) the worker is allowed to consume (0=unlimited,default)')

def check_mem(cb, *args, **kwargs):
    """ Checks for our current memory usage - if it exceeds the limit
    we exit and let the nanny restart us.
    """
    if config.MAXIMUM_WORKER_MEMORY > 0:
        mem = open("/proc/%s/statm" % os.getpid()).read().split()
        if int(mem[1])*4096/1024/1024 > config.MAXIMUM_WORKER_MEMORY:
            pyflaglog.log(pyflaglog.WARNING, "Process resident memory exceeds threshold. Exiting")
            cb(*args, **kwargs)

class Task:
    """ All distributed tasks need to extend this subclass """
    def run(self, **kwargs):
        """ This method is called in the worker to run """

config.add_option("WORKERS", default=2, type='int',
                  help='Number of workers to start up')

config.add_option("FIFO", default=config.RESULTDIR + "/jobs",
                  help = "The fifo to use for distributing jobs")

def worker_run(keepalive=None):
     """ The main loop of the worker.

     We never exit from this function.
     
     We use the keepalive to check that our parent is still alive. If
     it is not (i.e. the other end of the pipe returns failed reads),
     we quit.
     """
     FlagFramework.post_event("worker_startup")            
     my_pid = os.getpid()
     
     ## Open the pipes
     try:
         os.mkfifo(config.FIFO)
     except OSError,e:
         pass

     global job_pipe
     
     read_pipe = open(config.FIFO, "r")
     job_pipe = open(config.FIFO, "w")

     ## Jobs tdb keeps track of outstanding jobs
     job_tdb = get_job_tdb()
     
     while 1:
         fds = [read_pipe]
         if keepalive:
             fds.append(keepalive)
             
         ## This blocks until a job is available
         fds = select.select(fds, [], [], None)
         if keepalive in fds[0]:
             ## Action on the keepalive fd means the parent quit
             print "Child %s exiting" % os.getpid()
             os._exit(0)

         data = os.read(read_pipe.fileno(), PACKET_SIZE)
         command, argdict, cookie = pickle.loads(data)

         try:
             task = Registry.TASKS.dispatch(command)
         except:
             pyflaglog.log(pyflaglog.DEBUG, "Dont know how to process job %s" % command)
             continue

         try:
             task = task()
             task.run(cookie=cookie, **argdict)
         except Exception,e:
             raise
             pyflaglog.log(pyflaglog.ERRORS, "Error %s %s %s" % (task.__class__.__name__,argdict,e))

         ## Decrement the cookie in the jobs_tdb
         job_tdb.lock()
         try:
             count = int(job_tdb.get("%s" % cookie)) - 1
             job_tdb.store(str(cookie), str(count))
         except (KeyError, TypeError):
             job_tdb.store(str(cookie), str(0))
             
         job_tdb.unlock()

def start_workers():
    print "%s: starting workers" % os.getpid()
    global job_pipe
    children = []

    ## These pipes control the worker. If the master exits, the pipes
    ## will be closed which will notify the worker immediately. It
    ## will then exit.
    keepalive,w = os.pipe()

    ## Start up as many children as needed
    for i in range(config.WORKERS):
        pid = os.fork()
        if pid:
            children.append(pid)

        else:
            os.close(w)

            ## Initialise the worker
            worker_run(keepalive)
            sys.exit(0)
            
    ## The process which called this function is a master
    FlagFramework.post_event("startup")

def get_job_tdb():
    global job_tdb
    
    if not job_tdb:
        job_tdb = pytdb.PyTDB("%s/jobs.tdb" % config.RESULTDIR)

    return job_tdb

def post_job(command, argdict={}, cookie=0):
    global job_pipe

    if not job_pipe:
        job_pipe = open(config.FIFO, "w")

    job_tdb = get_job_tdb()
    
    ## Serialise the command for transmission across the pipe. We
    ## increment the count of the cookie in the job_tdb:
    job_tdb.lock()
    try:
        count = int(job_tdb.get(str(cookie))) + 1
        job_tdb.store(str(cookie), str(count))
    except (KeyError, TypeError):
        job_tdb.store(str(cookie), str(1))

    job_tdb.unlock()
    
    data = pickle.dumps((command, argdict, cookie))
    if len(data) > PACKET_SIZE:
        print "Error: data is larger than packet size... "
        os._exit(1)
        
    res = os.write(job_pipe.fileno(), data + bytearray(PACKET_SIZE - len(data)))
    
    return res

def get_cookie_reference(cookie):
    job_tdb = get_job_tdb()
    cookie = str(cookie)
    
    try:
        result = int(job_tdb.get(cookie))
        if result == 0:
            job_tdb.delete(cookie)
        return result
    except (KeyError, TypeError):
        return 0

if __name__=="__main__":
    ## If run by ourselves we just run a single worker
    import pyflag.Registry as Registry
    import pyflag.conf
    config=pyflag.conf.ConfObject()

    config.set_usage(usage = "PyFlag Worker")

    Registry.Init()

    config.parse_options()


    worker_run()
