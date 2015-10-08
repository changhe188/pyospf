#!/usr/bin/env python
# -*- coding:utf-8 -*-

import threading


class Timer(threading.Thread):
    """
    a timer that execute an action at the end of the timer run.
    """

    def __init__(self, seconds, action=None, args=None, once=False):
        self.counter = 0
        self.runTime = seconds
        self.args = args
        self.action = action
        self.stopEvent = threading.Event()
        self.once = once
        threading.Thread.__init__(self, args=self.stopEvent)
        #Set all timer threads daemon. When main thread exits, all threads exit.
        self.setDaemon(True)
        self.resetFlag = True
        self.stopFlag = False

    def run(self):
        while not self.stopFlag:
            while self.resetFlag and not self.stopFlag:
                self.stopEvent.clear()
                self.resetFlag = False
                self.stopEvent.wait(self.runTime)
            if not self.resetFlag and not self.stopFlag:
                if self.action:
                    if self.args:
                        self.action(self.args)
                    else:
                        self.action()
            if self.once:
                self.stopFlag = True
            self.resetFlag = True
        else:
            self.stopEvent.set()

    def reset(self, runtime=None):
        if runtime:
            self.runTime = runtime
        self.resetFlag = True
        self.stopEvent.set()

    def stop(self):
        self.stopFlag = True
        self.stopEvent.set()

    def get_counter(self):
        return self.counter

    def is_stop(self):
        return self.stopEvent.isSet()

