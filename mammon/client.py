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

import asyncio
import time
import socket
import copy

from ircreactor.envelope import RFC1459Message
from .utility import CaseInsensitiveDict, uniq
from .property import user_property_items, user_mode_items
from .server import eventmgr_rfc1459, get_context
from . import __version__

REGISTRATION_LOCK_NICK = 0x1
REGISTRATION_LOCK_USER = 0x2
REGISTRATION_LOCK_DNS  = 0x4

class ClientHistoryEntry(object):
    def __init__(self, cli):
        self.nickname = cli.nickname
        self.username = cli.username
        self.hostname = cli.hostname
        self.realname = cli.realname
        self.account = cli.account
        self.ctx = cli.ctx

    def register(self):
        self.ctx.client_history[self.nickname] = self

# XXX - handle ping timeout
# XXX - exit() could eventually be handled using self.eventmgr.dispatch()
class ClientProtocol(asyncio.Protocol):
    def connection_made(self, transport):
        self.ctx = get_context()

        self.peername = transport.get_extra_info('peername')
        self.transport = transport
        self.recvq = list()
        self.channels = list()
        self.nickname = '*'
        self.username = str()
        self.hostname = self.peername[0]  # XXX - handle rdns...
        self.realaddr = self.peername[0]
        self.realname = '<unregistered>'
        self.props = CaseInsensitiveDict()
        self.servername = self.ctx.conf.name

        self.away_message = str()
        self.operator = None              # XXX - update when operator objects are implemented
        self.account = None               # XXX - update if needed when account objects are implemented

        self.connected = True
        self.registered = False
        self.registration_lock = 0
        self.push_registration_lock(REGISTRATION_LOCK_NICK | REGISTRATION_LOCK_USER | REGISTRATION_LOCK_DNS)

        self.ctx.logger.debug('new inbound connection from {}'.format(self.peername))
        self.eventmgr = eventmgr_rfc1459

        asyncio.async(self.do_rdns_check())

    def update_idle(self):
        self.last_event_ts = self.ctx.eventloop.time()

    @property
    def idle_time(self):
        return int(self.ctx.eventloop.time() - self.last_event_ts)

    def connection_lost(self, exc):
        """Handle loss of connection if it was already not handled.
        Calling exit() can cause this function to be called recursively, so we use IClient.connected
        as a property to determine whether or not the client is still connected.  If we have already handled
        this connection loss (most likely by inducing it in exit()), then IClient.connected will be
        False.
        Side effects: IProtocol.exit() is called by this function."""
        if not self.connected:
            return
        if not exc:
            self.exit('Connection closed')
            return
        self.exit('Connection error: ' + repr(exc))

    def do_rdns_check(self):
        """Handle looking up the client's reverse DNS and validating it as a coroutine."""
        self.dump_notice('Looking up your hostname...')

        rdns = yield from self.ctx.eventloop.getnameinfo(self.peername)
        if rdns[0] == self.realaddr:
            self.dump_notice('Could not find your hostname...')
            self.release_registration_lock(REGISTRATION_LOCK_DNS)
            return

        try:
            fdns = yield from self.ctx.eventloop.getaddrinfo(rdns[0], rdns[1], proto=socket.IPPROTO_TCP)
            for fdns_e in fdns:
                if fdns_e[4][0] == self.realaddr:
                    self.dump_notice('Found your hostname: ' + rdns[0])
                    self.hostname = rdns[0]
                    self.release_registration_lock(REGISTRATION_LOCK_DNS)
                    return
        except:
            pass

        self.dump_notice('Could not find your hostname...')
        self.release_registration_lock(REGISTRATION_LOCK_DNS)

    def data_received(self, data):
        [self.message_received(m) for m in data.splitlines()]

    def message_received(self, data):
        m = RFC1459Message.from_message(data.decode('UTF-8', 'replace').strip('\r\n'))
        m.client = self

        # logging.debug('client {0} --> {1}'.format(repr(self.__dict__), repr(m.serialize())))
        if len(self.recvq) > self.ctx.conf.recvq_len:
            self.exit('Excess flood')
            return

        self.recvq.append(m)

        # XXX - drain_queue should be called on all objects at once to enforce recvq limits
        self.drain_queue()

    def drain_queue(self):
        while self.recvq:
            m = self.recvq.pop(0)
            self.eventmgr.dispatch(*m.to_event())

    # handle a mandatory side effect resulting from rfc1459.
    def handle_side_effect(self, msg, params=[]):
        m = RFC1459Message.from_data(msg, source=self.hostmask, params=params)
        m.client = self
        self.eventmgr.dispatch(*m.to_event())

    def dump_message(self, m):
        self.transport.write(bytes(m.to_message() + '\r\n', 'UTF-8'))

    def dump_numeric(self, numeric, params):
        msg = RFC1459Message.from_data(numeric, source=self.ctx.conf.name, params=[self.nickname] + params)
        self.dump_message(msg)

    def dump_notice(self, message):
        msg = RFC1459Message.from_data('NOTICE', source=self.ctx.conf.name, params=[self.nickname, '*** ' + message])
        self.dump_message(msg)

    @property
    def hostmask(self):
        if not self.registered:
            return None
        hm = self.nickname
        if self.username:
            hm += '!' + self.username
            if self.hostname:
                hm += '@' + self.hostname
        return hm

    @property
    def status(self):
        st = str()
        if self.away_message:
            st += 'G'
        else:
            st += 'H'
        if self.operator:
            st += '*'
        return st

    def exit(self, message):
        m = RFC1459Message.from_data('QUIT', source=self.hostmask, params=[message])
        self.sendto_common_peers(m)
        self.connected = False
        self.transport.close()
        if not self.registered:
            return
        while self.channels:
            i = self.channels.pop(0)
            i.channel.part(self)
        self.ctx.clients.pop(self.nickname)
        ClientHistoryEntry(self).register()

    def push_registration_lock(self, lock):
        if self.registered:
            return
        self.registration_lock |= lock

    def release_registration_lock(self, lock):
        if self.registered:
            return
        self.registration_lock &= ~lock
        if not self.registration_lock:
            self.register()

    @property
    def legacy_modes(self):
        out = '+'
        for i in self.props.keys():
            if self.props[i] and i in user_property_items:
                out += user_property_items[i]
        return out

    def set_legacy_modes(self, in_str):
        before = copy.deepcopy(self.props)

        mod = False
        for i in in_str:
            if i == '+':
                mod = True
            elif i == '-':
                mod = False
            else:
                if i == 'o' and mod == True:
                    continue
                if i not in user_mode_items:
                    self.dump_numeric('501', [i, 'Unknown MODE flag'])
                    continue
                prop = user_mode_items[i]
                self.props[prop] = mod

        self.flush_legacy_mode_change(before, self.props)

    def flush_legacy_mode_change(self, before, after):
        out = str()
        mod = 0

        for i in user_property_items.keys():
            if before.get(i, False) and not after.get(i, False):
                if mod == 1:
                    out += user_property_items[i]
                else:
                    mod = 1
                    out += '-'
                    out += user_property_items[i]
            elif not before.get(i, False) and after.get(i, False):
                if mod == 2:
                    out += user_property_items[i]
                else:
                    mod = 2
                    out += '+'
                    out += user_property_items[i]

        msg = RFC1459Message.from_data('MODE', source=self.hostmask, params=[self.nickname, out])
        self.dump_message(msg)

    def sendto_common_peers(self, message, exclude=[]):
        base = [i.client for m in self.channels for i in m.channel.members if i.client not in exclude] + [self]
        peerlist = uniq(base)
        [i.dump_message(message) for i in peerlist]

    def dump_isupport(self):
        isupport_tokens = {'NETWORK': self.ctx.conf.network, 'CLIENTVER': '3.2', 'CASEMAPPING': 'ascii', 'CHARSET': 'utf-8', 'SAFELIST': True}
        # XXX - split into multiple 005 lines if > 13 tokens
        def format_token(k, v):
            if isinstance(v, bool):
                return k
            return '{0}={1}'.format(k, v)

        self.dump_numeric('005', [format_token(k, v) for k, v in isupport_tokens.items()] + ['are supported by this server'])

    def register(self):
        self.registered = True
        self.ctx.clients[self.nickname] = self

        self.registration_ts = self.ctx.eventloop.time()
        self.update_idle()

        self.dump_numeric('001', ['Welcome to the ' + self.ctx.conf.network + ' IRC Network, ' + self.hostmask])
        self.dump_numeric('002', ['Your host is ' + self.ctx.conf.name + ', running version mammon-' + str(__version__)])
        self.dump_numeric('003', ['This server was started at ' + self.ctx.startstamp])
        self.dump_numeric('004', [self.ctx.conf.name, 'mammon-' + str(__version__), ''.join(user_mode_items.keys())])
        self.dump_isupport()

        # XXX - LUSERS isn't implemented.
        # self.handle_side_effect('LUSERS')
        self.handle_side_effect('MOTD')
