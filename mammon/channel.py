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

from ircreactor.envelope import RFC1459Message
from .utility import validate_chan, CaseInsensitiveDict
from .property import member_property_items, channel_property_items, channel_flag_items
import copy
from ircmatch import match

class ChannelManager(object):
    def __init__(self, ctx):
        self.ctx = ctx

    def get(self, name, create=False):
        if not validate_chan(name):
            return None
        ch = self.ctx.channels.get(name, None)
        if ch or not create:
            return ch
        ch = Channel(name)
        self.ctx.channels[name] = ch
        return ch

class ChannelMembership(object):
    def __init__(self, client, channel):
        self.client = client
        self.channel = channel
        self.props = CaseInsensitiveDict()

    @property
    def name(self):
        pstr = str()
        for prop, flag in member_property_items.items():
            if self.props.get(prop, False):
                pstr += flag
        pstr += self.client.nickname
        return pstr

    @property
    def who_status(self):
        pstr = self.client.status
        for prop, flag in member_property_items.items():
            if self.props.get(prop, False):
                pstr += flag
        return pstr

    @property
    def channel_name(self):
        pstr = str()
        for prop, flag in member_property_items.items():
            if self.props.get(prop, False):
                pstr += flag
        pstr += self.channel.name
        return pstr

class Channel(object):
    def __init__(self, name):
        self.name = name
        self.members = []
        self.topic = str()
        self.topic_setter = str()
        self.topic_ts = 0
        self.props = CaseInsensitiveDict()
        self.props_ts = 0
        self.user_set_metadata = []
        self.metadata = CaseInsensitiveDict()

    def authorize(self, cli, ev_msg):
        if 'key' in self.props and (len(ev_msg['params']) < 2 or self.props['key'] != ev_msg['params'][1]):
            cli.dump_numeric('475', [self.name, 'Cannot join channel (+k) - bad key'])
            return False
        if 'exempt' in self.props:
            for e in self.props['exempt']:
                if match(0, e, cli.hostmask):
                    return True
        if 'ban' in self.props:
            for b in self.props['ban']:
                if match(0, b, cli.hostmask):
                    cli.dump_numeric('474', [self.name, 'You are banned.'])
                    return False
        if 'invite' in self.props and 'invite-exemption' in self.props:
            for i in self.props['invite-exemption']:
                if match(0, i, cli.hostmask):
                    return True
                # XXX - /invite command
            return False
        return True

    def join(self, client):
        has_members = len(self.members) != 0
        m = ChannelMembership(client, self)
        self.members.append(m)
        client.channels.append(m)
        if not has_members:
            m.props['op'] = True
            msg = RFC1459Message.from_data('MODE', source=client.hostmask, params=[self.name, "+o", client.nickname])
            self.dump_message(msg)

    def part(self, client):
        for m in filter(lambda x: x.client == client, self.members):
            self.members.remove(m)
            if m in client.channels:
                client.channels.remove(m)

    def has_member(self, client):
        matches = tuple(filter(lambda x: x.client == client, self.members))
        return len(matches) > 0

    def get_member(self, client):
        matches = tuple(filter(lambda x: x.client == client, self.members))
        return len(matches) > 0 and matches[0]

    def find_member(self, nickname):
        matches = tuple(filter(lambda x: x.client.nickname == nickname, self.members))
        return len(matches) > 0 and matches[0]

    def can_send(self, client):
        member = self.get_member(client)
        if not self.props.get('allow-external', False) and not member:
            return False
        if self.props.get('moderated', False):
            if member.props.get('op', False) or member.props.get('voice', False):
                return True
            return False
        return True

    def can_display(self, client):
        if self.props.get('secret', False):
            return True
        return self.has_member(client)

    def dump_message(self, msg, exclusion_list=None):
        if not exclusion_list:
            exclusion_list = list()
        [m.client.dump_message(msg) for m in self.members if m.client not in exclusion_list]

    def set_legacy_modes(self, client, in_str, args):

        before = copy.deepcopy(self.props)
        before_users = copy.deepcopy({member.client.nickname: member.props for member in self.members})

        mod = False
        for i in in_str:
            if i == '+':
                mod = True
            elif i == '-':
                mod = False
            else:
                if i not in channel_flag_items:
                    client.dump_numeric('472', [i, 'is an unknown mode char to me'])
                    continue
                prop = channel_flag_items[i]
                if prop == 'ban' or prop == 'invite-exemption' or prop == 'exemption' or prop == 'quiet':
                    if prop not in self.props:
                        self.props[prop] = CaseInsensitiveDict()
                    if len(args) == 0:
                        for user, info in self.props[prop].items():
                            client.dump_numeric('367', [self.name, user, info[0], info[1]])
                        client.dump_numeric('368', [self.name, 'End of Channel '+prop.title()+' List'])
                        continue
                    arg = args.pop(0)
                    if mod == False and arg in self.props[prop]:
                        del(self.props[prop][arg])
                    if mod == True:
                        self.props[prop][arg] = (client.hostmask, client.ctx.current_ts)
                    continue
                if prop == 'key' or prop == 'limit' or prop == 'join-throttle' or prop == 'forward':
                    if len(args) > 0:
                        self.props[prop] = args.pop(0)
                    continue
                if prop == 'op' or prop == 'voice':
                    usr = args.pop(0)
                    member = self.find_member(usr)
                    if not member:
                        client.dump_numeric('401', [self.name, usr, "No such nick/channel"])
                        continue
                    member.props[prop] = mod
                    continue
                self.props[prop] = mod

        self.flush_legacy_mode_change(client, before, self.props,
                                      before_users, {member.client.nickname: member.props for member in self.members})


    def flush_legacy_mode_change(self, cli, before, after, before_users, after_users):
        out = str()
        args = []
        mod = 0

        for i in channel_property_items.keys():
            if before.get(i, False) and not after.get(i, False):
                if mod == 1:
                    if i == 'ban' or i == 'quiet' or i == 'invite-exemption' or i == 'exemption':
                        for j in before.get(i, []):
                            if j not in after.get(i):
                                out += channel_property_items[i]
                                args.append(j)
                        continue
                    out += channel_property_items[i]
                    if before.get(i, False) != True:
                        args.append(before.get(i))
                else:
                    mod = 1
                    out += '-'
                    if i == 'ban' or i == 'quiet' or i == 'invite-exemption' or i == 'exemption':
                        for j in before.get(i, []):
                            if j not in after.get(i):
                                out += channel_property_items[i]
                                args.append(j)
                        continue
                    out += channel_property_items[i]
                    if before.get(i, False) != True:
                        args.append(before.get(i))
            elif not before.get(i, False) and after.get(i, False):
                if mod == 2:
                    if i == 'ban' or i == 'quiet' or i == 'invite-exemption' or i == 'exemption':
                        for j in after.get(i):
                            if j not in before.get(i, []):
                                out += channel_property_items[i]
                                args.append(j)
                        continue
                    out += channel_property_items[i]
                    if after.get(i, False) != True:
                        args.append(after.get(i))
                else:
                    mod = 2
                    out += '+'
                    if i == 'ban' or i == 'quiet' or i == 'invite-exemption' or i == 'exemption':
                        for j in after.get(i):
                            if j not in before.get(i, []):
                                out += channel_property_items[i]
                                args.append(j)
                        continue
                    out += channel_property_items[i]
                    if after.get(i, False) != True:
                        args.append(after.get(i))
            for nick, flags in before_users.items():
                if flags.get(i) and not after_users[nick].get(i):
                    if mod == 1:
                        out += channel_property_items[i]
                        args.append(nick)
                    else:
                        mod = 1
                        out += '-'
                        out += channel_property_items[i]
                        args.append(nick)
            for nick, flags in after_users.items():
                if flags.get(i) and not before_users[nick].get(i):
                    if mod == 1:
                        out += channel_property_items[i]
                        args.append(nick)
                    else:
                        mod = 1
                        out += '+'
                        out += channel_property_items[i]
                        args.append(nick)

        msg = RFC1459Message.from_data('MODE', source=cli.hostmask, params=[self.name, out] + args)
        self.dump_message(msg)

    @property
    def legacy_modes(self):
        args = ['+']
        for i in self.props.keys():
            if self.props[i] != False and i in channel_property_items \
                    and not (i == 'ban' or i == 'quiet' or i == 'invite-exemption' or i == 'exemption'):
                args[0] += channel_property_items[i]
                if self.props[i] != True:
                    args.append(self.props[i])
        return ' '.join(args)

    @property
    def classification(self):
        if not 'secret' in self.props:
            return '='
        return '@'

# --- rfc1459 channel management commands ---
from .events import eventmgr_rfc1459

@eventmgr_rfc1459.message('JOIN', min_params=1, update_idle=True)
def m_JOIN(cli, ev_msg):
    chanlist = ev_msg['params'][0].split(',')

    for chan in chanlist:
        if not validate_chan(chan):
            cli.dump_numeric('479', [chan, 'Illegal channel name'])
            return
        ch = cli.ctx.chmgr.get(chan, create=True)
        if ch.has_member(cli):
            continue
        if not ch.authorize(cli, ev_msg):
            continue

        ch.join(cli)
        ch.dump_message(RFC1459Message.from_data('JOIN', source=cli.hostmask, params=[ch.name]))

        if ch.topic:
            cli.handle_side_effect('TOPIC', params=[ch.name])

        cli.handle_side_effect('NAMES', params=[ch.name])

@eventmgr_rfc1459.message('PART', min_params=1, update_idle=True)
def m_PART(cli, ev_msg):
    chanlist = ev_msg['params'][0].split(',')

    for chan in chanlist:
        if not validate_chan(chan):
            cli.dump_numeric('479', [ev_msg['params'][0], 'Illegal channel name'])
            return

        ch = cli.ctx.chmgr.get(chan, create=False)
        if not ch:
            cli.dump_numeric('403', [chan, 'No such channel'])
            return

        if not ch.has_member(cli):
            cli.dump_numeric('442', [ch.name, "You're not on that channel"])
            return

        ch.dump_message(RFC1459Message.from_data('PART', source=cli.hostmask, params=ev_msg['params']))
        ch.part(cli)

@eventmgr_rfc1459.message('NAMES', min_params=1)
def m_NAMES(cli, ev_msg):
    chanlist = ev_msg['params'][0].split(',')

    for chan in chanlist:
        if not validate_chan(chan):
            cli.dump_numeric('479', [chan, 'Illegal channel name'])
            return

        ch = cli.ctx.chmgr.get(ev_msg['params'][0], create=False)
        if not ch:
            cli.dump_numeric('403', [chan, 'No such channel'])
            return

        names_f = lambda x: True
        if not ch.has_member(cli):
            names_f = lambda x: 'user:invisible' not in x.client.props

        # XXX - this may need to be split up if we start enforcing an outbound packet size
        cli.dump_numeric('353', [ch.classification, ch.name, ' '.join([m.name for m in filter(names_f, ch.members)])])
        cli.dump_numeric('366', [ch.name, 'End of /NAMES list.'])

@eventmgr_rfc1459.message('TOPIC', min_params=1, update_idle=True)
def m_TOPIC(cli, ev_msg):
    chanlist = ev_msg['params'][0].split(',')

    for chan in chanlist:
        if not validate_chan(chan):
            cli.dump_numeric('479', [chan, 'Illegal channel name'])
            return

        ch = cli.ctx.chmgr.get(chan, create=False)
        if not ch:
            cli.dump_numeric('403', [chan, 'No such channel'])
            continue

        if not ch.has_member(cli):
            cli.dump_numeric('442', [ch.name, "You're not on that channel"])
            continue

        if not ch.get_member(cli).props.get('op', False) and ch.props.get('op-topic'):
            cli.dump_numeric('482', [ch.name, 'You\'re not a channel operator'])
            continue

        # handle inquiry
        if len(ev_msg['params']) == 1:
            if ch.topic:
                cli.dump_numeric('332', [ch.name, ch.topic])
                cli.dump_numeric('333', [ch.name, ch.topic_setter, ch.topic_ts])
                continue

            cli.dump_numeric('331', [ch.name, 'No topic is set'])
            continue

        # handle setting
        ch.topic = ev_msg['params'][1]
        ch.topic_setter = cli.hostmask
        ch.topic_ts = cli.ctx.current_ts

        # distribute new topic to peers
        ch.dump_message(RFC1459Message.from_data('TOPIC', source=cli.hostmask, params=[ch.name, ch.topic]))

# XXX - handle ELIST
@eventmgr_rfc1459.message('LIST')
def m_LIST(cli, ev_msg):
    cli.dump_numeric('321', ['Channel', 'Users', 'Topic'])

    for ch_name, ch in cli.ctx.channels.items():
        if ch.can_display(cli):
            cli.dump_numeric('322', [ch.name, str(len(ch.members)), ch.topic])

    cli.dump_numeric('323', ['End of /LIST'])
