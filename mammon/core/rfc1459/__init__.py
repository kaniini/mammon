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
import ircmatch

from mammon import __credits__, __version__
from mammon.utility import validate_nick, validate_chan
from mammon.events import eventmgr_core, eventmgr_rfc1459
from mammon.server import get_context

# - - - BUILTIN RFC1459 EVENTS - - -

from . import away

@eventmgr_rfc1459.message('KILL', min_params=2)
def m_KILL(cli, ev_msg):
    target, reason = ev_msg['params'][:2]

    # XXX - when we have multiple servers, we will need to check local kill vs remote kill
    if (cli.role and 'oper:local_kill' not in cli.role.capabilities) or not cli.role:
        cli.dump_numeric('481', ['Permission Denied'])
        return

    # XXX - check other servers too when we have multiple servers
    server_hostnames = [cli.ctx.conf.server['name']]
    if target in server_hostnames:
        cli.dump_numeric('483', [target, "You can't kill a server!"])
        return

    cli_tg = cli.ctx.clients.get(target, None)
    if not cli_tg:
        cli.dump_numeric('401', [target, 'No such nick/channel'])
        return

    cli_tg.kill(cli, reason)

@eventmgr_rfc1459.message('OPER', min_params=2)
def m_OPER(cli, ev_msg):
    name, password = ev_msg['params'][:2]

    # make sure hostmask is valid, if defined in config
    valid_hosts = [data.get('hostmask', None) for data in cli.ctx.conf.opers.values()]
    if None not in valid_hosts:
        have_a_valid_host = False

        for hostmask in valid_hosts:
            if ircmatch.match(0, hostmask, cli.hostmask):
                have_a_valid_host = True
                break

        if not have_a_valid_host:
            cli.dump_numeric('491', ['No O-lines for your host'])
            return

    data = cli.ctx.conf.opers.get(name, None)
    if data is not None:
        pass_is_valid = False

        hash = data.get('hash', None)
        if hash:
            if hash not in cli.ctx.hashing.valid_schemes:
                print('mammon: error: hashing algorithm for oper password is not valid')
            elif cli.ctx.hashing.enabled:
                pass_is_valid = cli.ctx.hashing.verify(password, data.get('password'))
            else:
                print('mammon: error: cannot verify oper password, hashing is not enabled')
        else:
            pass_is_valid = password == data.get('password')

        del password

        # check this specific oper's hostmask
        hostmask = data.get('hostmask')
        if not ircmatch.match(0, hostmask, cli.hostmask):
            # we do this so we don't leak info on oper blocks
            pass_is_valid = False

    if pass_is_valid:
        if data.get('role') in cli.ctx.roles:
            cli.role = data.get('role')
        else:
            print('mammon: error: role does not exist for oper', name)

        cli.props['special:oper'] = True
        cli.dump_numeric('381', ['You are now an IRC operator'])
    else:
        cli.dump_numeric('464', ['Password incorrect'])

@eventmgr_rfc1459.message('QUIT', allow_unregistered=True)
def m_QUIT(cli, ev_msg):
    reason = ev_msg['params'][0] if ev_msg['params'] else str()
    cli.quit('Quit: ' + reason)

@eventmgr_rfc1459.message('NICK', min_params=1, allow_unregistered=True)
def m_NICK(cli, ev_msg):
    new_nickname = ev_msg['params'][0]
    if not validate_nick(new_nickname):
        cli.dump_numeric('432', [new_nickname, 'Erroneous nickname'])
        return
    if new_nickname in cli.ctx.clients:
        cli.dump_numeric('433', [new_nickname, 'Nickname already in use'])
        return
    msg = RFC1459Message.from_data('NICK', source=cli.hostmask, params=[new_nickname])
    if cli.registered:
        if cli.nickname in cli.ctx.clients:
            cli.ctx.clients.pop(cli.nickname)
        cli.ctx.clients[new_nickname] = cli
        cli.sendto_common_peers(msg)
    cli.nickname = new_nickname
    cli.release_registration_lock('NICK')

@eventmgr_rfc1459.message('USER', min_params=4, allow_unregistered=True)
def m_USER(cli, ev_msg):
    new_username = ev_msg['params'][0]
    new_realname = ev_msg['params'][3]
    cli.username = new_username
    cli.realname = new_realname
    cli.release_registration_lock('USER')

@eventmgr_rfc1459.message('PING', allow_unregistered=True)
def m_PING(cli, ev_msg):
    reply = ev_msg['params'][0] if ev_msg['params'] else cli.ctx.conf.name
    msg = RFC1459Message.from_data('PONG', source=cli.ctx.conf.name, params=[reply])
    cli.dump_message(msg)

@eventmgr_rfc1459.message('PONG', min_params=1, allow_unregistered=True)
def m_PONG(cli, ev_msg):
    if cli.ping_cookie and int(ev_msg['params'][0]) != cli.ping_cookie:
        return
    cli.last_pong = cli.ctx.current_ts

@eventmgr_rfc1459.message('INFO')
def m_INFO(cli, ev_msg):
    lines = __credits__.splitlines()
    for line in lines:
        cli.dump_numeric('371', [line])
    cli.dump_numeric('374', ['End of /INFO list.'])

@eventmgr_rfc1459.message('VERSION')
def m_VERSION(cli, ev_msg):
    cli.dump_numeric('351', ['mammon-' + str(__version__), cli.ctx.conf.name])
    cli.dump_isupport()

@eventmgr_rfc1459.message('PRIVMSG', min_params=2, update_idle=True)
def m_PRIVMSG(cli, ev_msg):
    targetlist = ev_msg['params'][0].split(',')
    message = ev_msg['params'][1]

    for target in targetlist:
        if target[0] != '#':
            cli_tg = cli.ctx.clients.get(target, None)
            if not cli_tg:
                cli.dump_numeric('401', [target, 'No such nick/channel'])
                continue
            eventmgr_core.dispatch('client message', {
                'source': cli,
                'target': cli_tg,
                'target_name': target,
                'message': message,
            })
            continue

        ch = cli.ctx.chmgr.get(target)
        if not ch:
            cli.dump_numeric('401', [target, 'No such nick/channel'])
            continue

        if not ch.can_send(cli):
            cli.dump_numeric('404', [ch.name, 'Cannot send to channel'])
            continue

        eventmgr_core.dispatch('channel message', {
            'source': cli,
            'target': ch,
            'target_name': target,
            'message': message,
        })

@eventmgr_core.handler('client message')
def m_privmsg_client(info):
    ctx = get_context()
    if ctx.conf.name == info['target'].servername:
        msg = RFC1459Message.from_data('PRIVMSG', source=info['source'].hostmask, params=[info['target_name'], info['message']])
        info['target'].dump_message(msg)

@eventmgr_core.handler('channel message')
def m_privmsg_channel(info):
    msg = RFC1459Message.from_data('PRIVMSG', source=info['source'].hostmask, params=[info['target_name'], info['message']])
    # XXX - when we have s2s, make sure we only dump messages to local clients here or in dump_message
    info['target'].dump_message(msg, exclusion_list=[info['source']])

@eventmgr_rfc1459.message('NOTICE', min_params=2)
def m_NOTICE(cli, ev_msg):
    targetlist = ev_msg['params'][0].split(',')
    message = ev_msg['params'][1]

    for target in targetlist:
        if target[0] != '#':
            cli_tg = cli.ctx.clients.get(target, None)
            if not cli_tg:
                continue
            msg = RFC1459Message.from_data('NOTICE', source=cli.hostmask, params=[cli_tg.nickname, message])
            cli_tg.dump_message(msg)
            continue

        ch = cli.ctx.chmgr.get(target)
        if not ch or not ch.can_send(cli):
            continue

        msg = RFC1459Message.from_data('NOTICE', source=cli.hostmask, params=[ch.name, message])
        ch.dump_message(msg, exclusion_list=[cli])

@eventmgr_rfc1459.message('MOTD')
def m_MOTD(cli, ev_msg):
    if cli.ctx.conf.motd:
        cli.dump_numeric('375', ['- ' + cli.ctx.conf.name + ' Message of the Day -'])
        for i in cli.ctx.conf.motd:
            cli.dump_numeric('372', ['- ' + i])
        cli.dump_numeric('376', ['End of /MOTD command.'])
    else:
        cli.dump_numeric('422', ['MOTD File is missing'])

@eventmgr_rfc1459.message('MODE', min_params=1)
def m_MODE(cli, ev_msg):
    if ev_msg['params'][0] == cli.nickname:
        if len(ev_msg['params']) == 1:
            cli.dump_numeric('221', [cli.legacy_modes])
            return
        cli.set_legacy_modes(ev_msg['params'][1])
        return
    elif ev_msg['params'][0][0] != '#':
        cli.dump_numeric('502', ["Can't change mode for other users"])
        return
    else:
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
            print(ev_msg)
            # handle inquiry
            if len(ev_msg['params']) == 1 or len(ev_msg['params'][1]) < 2:
                cli.dump_numeric('324', [ch.name, ch.legacy_modes])
                cli.dump_numeric('329', [ch.name, ch.props_ts])
                continue
            if not ch.get_member(cli).props.get('op', False):
                cli.dump_numeric('482', [ch.name, 'You\'re not a channel operator'])
                continue

            ch.set_legacy_modes(cli, ev_msg['params'][1], ev_msg['params'][2:])
            ch.props_ts = cli.ctx.current_ts

@eventmgr_rfc1459.message('ISON', min_params=1)
def m_ISON(cli, ev_msg):
    matches = []

    # charybdis implements it roughly this way.  rfc1459 is ambiguous, so we will
    # use charybdis's implementation.
    for chunk in ev_msg['params']:
        for subchunk in chunk.split():
            if subchunk in cli.ctx.clients:
                matches.append(subchunk)

    # ircII derivatives needs a trailing space, ugh.
    # unfortunately BitchX is ircv3.1 compliant so we actually have to care about this
    cli.dump_numeric('303', [' '.join(matches) + ' '])

# WHO 0 o
# WHO #channel
@eventmgr_rfc1459.message('WHO', min_params=1)
def m_WHO(cli, ev_msg):
    oper_query = False
    if len(ev_msg['params']) > 1:
        oper_query = 'o' in ev_msg['params'][1]

    def do_single_who(cli, tparam, target, status=None):
        if oper_query and not target.props.get('special:oper', False):
            return
        if not status:
            status = target.status
        cli.dump_numeric('352', [tparam, target.username, target.hostname, target.servername, target.nickname, status, '0 ' + target.realname])

    target = ev_msg['params'][0]
    if target[0] == '#':
        chan = cli.ctx.chmgr.get(target)
        if chan:
            [do_single_who(cli, target, i.client, i.who_status) for i in chan.members]
    else:
        u = cli.ctx.clients.get(target, None)
        if u:
            do_single_who(cli, target, u)

    cli.dump_numeric('315', [target, 'End of /WHO list.'])

# WHOIS nickname
@eventmgr_rfc1459.message('WHOIS', min_params=1)
def m_WHOIS(cli, ev_msg):
    target = ev_msg['params'][0]

    cli_tg = cli.ctx.clients.get(target, None)
    if not cli_tg:
        cli.dump_numeric('401', [target, 'No such nick/channel'])
        return

    channels = tuple(filter(lambda x: 'secret' not in x.channel.props or x.channel.has_member(cli), cli_tg.channels))

    cli.dump_numeric('311', [cli_tg.nickname, cli_tg.username, cli_tg.hostname, '*', cli_tg.realname])
    if channels:
        cli.dump_numeric('319', [cli_tg.nickname, ' '.join([x.channel_name for x in channels]) + ' '])
    cli.dump_numeric('312', [cli_tg.nickname, cli.ctx.conf.name, cli.ctx.conf.description])
    if cli_tg.role:
        cli.dump_numeric('313', [cli_tg.nickname, cli_tg.role.whois_line])
    if cli_tg.account:
        cli.dump_numeric('330', [cli_tg.nickname, cli_tg.account.name, 'is logged in as'])
    awaymsg = cli_tg.metadata.get('away', None)
    if awaymsg:
        cli.dump_numeric('301', [cli_tg.nickname, awaymsg])
    cli.dump_numeric('317', [cli_tg.nickname, cli_tg.idle_time, cli_tg.registration_ts, 'seconds idle, signon time'])
    cli.dump_numeric('318', [cli_tg.nickname, 'End of /WHOIS list.'])

# WHOWAS nickname
@eventmgr_rfc1459.message('WHOWAS', min_params=1)
def m_WHOWAS(cli, ev_msg):
    target = ev_msg['params'][0]

    whowas_entry = cli.ctx.client_history.get(target, None)
    if not whowas_entry:
        cli.dump_numeric('406', [target, 'There was no such nickname'])
        return

    cli.dump_numeric('314', [whowas_entry.nickname, whowas_entry.username, whowas_entry.hostname, '*', whowas_entry.realname])
    cli.dump_numeric('312', [whowas_entry.nickname, cli.ctx.conf.name, cli.ctx.conf.description])
    if whowas_entry.account:
        cli.dump_numeric('330', [whowas_entry.nickname, whowas_entry.account, 'was logged in as'])
    cli.dump_numeric('369', [whowas_entry.nickname, 'End of WHOWAS'])
