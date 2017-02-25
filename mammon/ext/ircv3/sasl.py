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

from mammon.events import eventmgr_core, eventmgr_rfc1459
from mammon.capability import Capability, caplist

import base64
import binascii

valid_mechanisms = ['PLAIN']

cap_sasl = Capability('sasl', value=','.join(valid_mechanisms))

@eventmgr_core.handler('server start')
def m_sasl_start(info):
    ctx = info['server']
    if not ctx.hashing.enabled:
        ctx.logger.info('SASL PLAIN disabled because hashing is not available')
        valid_mechanisms.remove('PLAIN')
    if len(valid_mechanisms) == 0:
        ctx.logger.info('SASL disabled because no mechanisms are available')
        del caplist['sasl']

@eventmgr_rfc1459.message('AUTHENTICATE', min_params=1, allow_unregistered=True)
def m_AUTHENTICATE(cli, ev_msg):
    if len(ev_msg['params']) == 1 and ev_msg['params'][0] == '*':
        if getattr(cli, 'sasl', None):
            cli.dump_numeric('906', ['SASL authentication aborted'])
        else:
            cli.dump_numeric('904', ['SASL authentication failed'])
        cli.sasl = None
        cli.sasl_tmp = ''
        return

    if getattr(cli, 'sasl', None):
        raw_data = ev_msg['params'][0]

        if len(raw_data) > 400:
            cli.dump_numeric('905', ['SASL message too long'])
            cli.sasl = None
            cli.sasl_tmp = ''
            return
        elif len(raw_data) == 400:
            if not hasattr(cli, 'sasl_tmp'):
                cli.sasl_tmp = ''
            cli.sasl_tmp += raw_data
            # allow 4 'continuation' lines before rejecting for length
            if len(cli.sasl_tmp) > 400 * 4:
                cli.dump_numeric('904', ['SASL authentication failed: Password too long'])
                cli.sasl = None
                cli.sasl_tmp = ''
            return
        elif getattr(cli, 'sasl_tmp', None):
            if raw_data != '+':
                cli.sasl_tmp += raw_data

        try:
            if hasattr(cli, 'sasl_tmp'):
                data = base64.b64decode(cli.sasl_tmp)
            else:
                data = base64.b64decode(raw_data)
        except binascii.Error:
            cli.dump_numeric('904', ['SASL authentication failed'])
            return

        cli.sasl_tmp = ''

        eventmgr_core.dispatch('sasl authenticate {}'.format(cli.sasl.casefold()), {
            'source': cli,
            'mechanism': cli.sasl,
            'data': data,
        })

    else:
        mechanism = ev_msg['params'][0].upper()
        if mechanism in valid_mechanisms:
            cli.sasl = mechanism
            cli.dump_verb('AUTHENTICATE', '+', unprefixed=True)
        else:
            cli.dump_numeric('904', ['SASL authentication failed'])
            return

@eventmgr_core.handler('client registered')
def m_sasl_unreglocked(info):
    cli = info['client']
    if getattr(cli, 'sasl', None):
        cli.sasl = None
        cli.dump_numeric('906', ['SASL authentication aborted'])

@eventmgr_core.handler('sasl authenticate plain')
def m_sasl_plain(info):
    cli = info['source']
    data = info['data']

    try:
        authorization_id, account, passphrase = data.split(b'\x00')
    except ValueError:
        cli.dump_numeric('904', ['SASL authentication failed'])
        cli.sasl = None
        return
    account = str(account, 'utf8')
    passphrase = str(passphrase, 'utf8')
    authorization_id = str(authorization_id, 'utf8')

    # Derive authorization_id from account name
    authorization_id = authorization_id or account

    account_info = cli.ctx.data.get('account.{}'.format(account), None)
    if (account_info and 'passphrase' in account_info['credentials'] and
            account_info['verified'] and authorization_id == account):
        passphrase_hash = account_info['credentials']['passphrase']
        if cli.ctx.hashing.verify(passphrase, passphrase_hash):
            cli.account = account
            eventmgr_core.dispatch('account change', {
                'source': cli,
                'account': account,
            })
            cli.sasl = None
            hostmask = cli.hostmask
            if hostmask is None:
                hostmask = '*'
            cli.dump_numeric('900', [hostmask, account, 'You are now logged in as {}'.format(account)])
            cli.dump_numeric('903', ['SASL authentication successful'])
            return
    cli.dump_numeric('904', ['SASL authentication failed'])
