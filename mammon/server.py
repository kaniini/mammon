#!/usr/bin/env python
# mammon - a useless ircd
#
# Copyright (c) 2015, William Pitcock <nenolod@dereferenced.org>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

from .events import EventManager, eventmgr_rfc1459, eventmgr_core

running_context = None

def get_context():
    global running_context
    return running_context

from . import core
from .config import ConfigHandler
from .hashing import HashHandler
from .utility import CaseInsensitiveDict, ExpiringDict
from .channel import ChannelManager
from .capability import caplist

import logging
import asyncio
import sys
import time
import os
import importlib
from getpass import getpass

class ServerContext(object):
    options = []
    roles = []
    clients = CaseInsensitiveDict()
    channels = CaseInsensitiveDict()
    listeners = []
    config_name = 'mammond.yml'
    nofork = False
    current_ts = None

    def __init__(self):
        self.logger = logging.getLogger('')
        self.logger.setLevel(logging.DEBUG)

        self.chmgr = ChannelManager(self)
        self.client_history = ExpiringDict(max_len=1024, max_age_seconds=86400)

        # must be done before handling command line
        self.hashing = HashHandler()

        self.handle_command_line()

        if not self.nofork:
            self.daemonize()

        self.logger.info('mammon - starting up, config: {0}'.format(self.config_name))
        self.eventloop = asyncio.get_event_loop()

        self.logger.debug('parsing configuration...')
        self.handle_config()

        self.logger.debug('init finished...')

        self.startstamp = time.strftime('%a %b %d %Y at %H:%M:%S %Z')

    def update_ts(self):
        self.current_ts = time.time()

    def daemonize(self):
        self.pid = os.fork()
        if self.pid < 0:
            sys.exit(1)
        if self.pid != 0:
            sys.exit(0)
        self.pid = os.setsid()
        if self.pid == -1:
            sys.exit(1)
        devnull = "/dev/null"
        if hasattr(os, "devnull"):
            devnull = os.devnull
        devnull_fd = os.open(devnull, os.O_RDWR)
        os.dup2(devnull_fd, 0)
        os.dup2(devnull_fd, 1)
        os.dup2(devnull_fd, 2)

    def usage(self):
        cmd = sys.argv[0]
        print("""{0} [options]
A useless ircd.

Options:
   --help              - This screen.
   --debug             - Enable debug verbosity
   --nofork            - Do not fork into background
   --config config     - A YAML configuration file to parse
   --list-hashes       - List the supported hashes for passwords
   --mkpasswd          - Return hashed password, to put into config files""".format(cmd))
        exit(1)

    def list_hashes(self):
        print('Valid hashing algorithms:', ', '.join(self.hashing.valid_schemes))
        exit(1)

    def mkpasswd(self):
        if not self.hashing.enabled:
            print('mammon: error: hashing is not enabled, try:  pip3 install passlib')
            exit(1)

        print('Valid hashing algorithms:', ', '.join(self.hashing.valid_schemes))

        scheme = 'invalid'
        prompt = 'Hashing algorithm [{default}]: '.format(default=self.hashing.default_scheme)
        while scheme != '' and scheme not in self.hashing.valid_schemes:
            scheme = input(prompt)
        if scheme == '':
            scheme = self.hashing.default_scheme

        password = ''
        prompt = 'Password: '
        while password.strip() == '':
            password = getpass(prompt)

        print('')

        hash = self.hashing.encrypt(password, scheme=scheme)
        print(hash)

        exit(1)

    def handle_command_line(self):
        if '--help' in sys.argv:
            self.usage()
        if '--list-hashes' in sys.argv:
            self.list_hashes()
        if '--mkpasswd' in sys.argv:
            self.mkpasswd()
        if '--config' in sys.argv:
            try:
                self.config_name = sys.argv[sys.argv.index('--config') + 1]
            except IndexError:
                print('mammon: error: no parameter provided for --config')
                exit(1)
        if '--debug' in sys.argv:
            logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)
        if '--nofork' in sys.argv:
            self.nofork = True

    def handle_config(self):
        self.conf = ConfigHandler(self.config_name, self)
        self.conf.process()
        self.open_listeners()
        self.open_logs()
        self.load_modules()

    def open_listeners(self):
        [asyncio.async(lstn) for lstn in self.listeners]

    def load_module(self, mod):
        try:
            importlib.import_module(mod)
        except:
            self.logger.info('rejecting module ' + mod + ' because it failed to import')

    def load_modules(self):
        [self.load_module(m) for m in self.conf.extensions]

    def open_logs(self):
        if self.conf.logs:
            for log in self.conf.logs:
                fh = logging.FileHandler(log['path'])
                fh.setLevel(logging.DEBUG)
                self.logger.addHandler(fh)

    def update_ts_callback(self):
        self.update_ts()
        self.eventloop.call_later(1, self.update_ts_callback)

    def run(self):
        global running_context
        running_context = self

        self.update_ts_callback()
        self.eventloop.run_forever()
        exit(0)
