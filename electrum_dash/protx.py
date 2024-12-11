# -*- coding: utf-8 -*-
#
# Dash-Electrum - lightweight Dash client
# Copyright (C) 2019 Dash Developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import copy
import threading

from . import constants, util
from .bitcoin import address_to_script, is_b58_address, b58_address_to_hash160
from .protx_list import MNList
from .dash_tx import (TxOutPoint, ProTxService, DashProRegTx, DashProUpServTx,
                      DashProUpRegTx, DashProUpRevTx,
                      SPEC_PRO_REG_TX, SPEC_PRO_UP_SERV_TX,
                      SPEC_PRO_UP_REG_TX, SPEC_PRO_UP_REV_TX, str_ip)
from .util import bfh, bh2u
from .json_db import StoredDict
from .logging import Logger


PROTX_TX_TYPES = [
    SPEC_PRO_REG_TX,
    SPEC_PRO_UP_SERV_TX,
    SPEC_PRO_UP_REG_TX,
    SPEC_PRO_UP_REV_TX
]


class ProTxMNExc(Exception): pass


class ProTxMN:
    '''
    Masternode data with next properties:

    alias               MN alias
    is_owned            This wallet is has owner_addr privk
    is_operated         This wallet must generate BLS privk
    bls_privk           Random BLS key

    type                MN type
    mode                MN mode
    collateral          TxOutPoint collateral data
    service             ProTxService masternode service data
    owner_addr          Address of MN owner pubkey
    pubkey_operator     BLS pubkey of MN operator
    voting_addr         Address of pubkey used for voting
    op_reward           Operator reward, a value from 0 to 10000
    payout_address      Payee address
    op_payout_address   Operator payee address

    protx_hash          Hash of ProRegTx transaction
    '''

    fields = ('alias is_owned is_operated bls_privk type mode '
              'collateral service owner_addr pubkey_operator voting_addr '
              'op_reward payout_address op_payout_address protx_hash').split()

    def __init__(self):
        self.alias = ''
        self.is_owned = True
        self.is_operated = True
        self.bls_privk = None

        self.type = 0
        self.mode = 0
        self.collateral = TxOutPoint('', -1)
        self.service = ProTxService('', self.default_port())
        self.owner_addr = ''
        self.pubkey_operator = ''
        self.voting_addr = ''
        self.op_reward = 0
        self.payout_address = ''
        self.op_payout_address = ''

        self.protx_hash = ''

    @classmethod
    def default_port(cls):
        return 19999 if constants.net.TESTNET else 9999

    def __repr__(self):
        f = ', '.join(['%s=%s' % (f, getattr(self, f)) for f in self.fields])
        return 'ProTxMN(%s)' % f

    def as_dict(self):
        res = {}
        for f in self.fields:
            v = copy.deepcopy(getattr(self, f))
            if isinstance(v, tuple):
                res[f] = dict(v._asdict())
            else:
                res[f] = v
        return res

    @classmethod
    def from_dict(cls, d):
        d = dict(d)
        mn = ProTxMN()
        for f in cls.fields:
            if f not in d:
                raise ProTxMNExc('Key %s is missing in supplied dict')
            v = d[f]
            if isinstance(v, StoredDict):
                v = dict(v)
            v = copy.deepcopy(v)
            if f == 'collateral':
                v['hash'] = bfh(v['hash'])[::-1]
                setattr(mn, f, TxOutPoint(**v))
            elif f == 'service':
                setattr(mn, f, ProTxService(**v))
            else:
                setattr(mn, f, v)
        return mn


class ProTxManagerExc(Exception): pass


class ProRegTxExc(Exception): pass


class ProTxManager(Logger):
    '''Class representing wallet DIP3 masternodes manager'''

    LOGGING_SHORTCUT = 'M'

    def __init__(self, wallet):
        Logger.__init__(self)
        self.wallet = wallet
        self.network = None
        self.mns = {}  # Wallet MNs
        self.manager_lock = threading.Lock()
        self.alias_updated = ''

    def with_manager_lock(func):
        def func_wrapper(self, *args, **kwargs):
            with self.manager_lock:
                return func(self, *args, **kwargs)
        return func_wrapper

    def notify(self, key):
        if key == 'manager-alias-updated':
            value = self.alias_updated
            self.alias_updated = ''
        else:
            value = None
        util.trigger_callback(key, value)

    def on_network_start(self, network):
        self.network = network
        self.update_mns_from_protx_list()
        util.register_callback(self.on_mn_list_diff_updated,
                               ['mn-list-diff-updated'])

    def clean_up(self):
        if self.network:
            util.unregister_callback(self.on_mn_list_diff_updated)

    @with_manager_lock
    def load(self):
        '''Load masternodes from wallet storage.'''
        stored_mns = self.wallet.db.get_protx_mns()
        self.mns = {k: ProTxMN.from_dict(d) for k, d in stored_mns.items()}

    def save(self, with_lock=True):
        '''Save masternodes to wallet storage with lock.'''
        if with_lock:
            with self.manager_lock:
                self._do_save()
        else:
            self._do_save()

    def _do_save(self):
        '''Save masternodes to wallet storage.'''
        stored_mns = {}
        for mn in self.mns.values():
            if not mn.alias:
                raise ProTxManagerExc('Attempt to write Masternode '
                                      'with empty alias')
            stored_mns[mn.alias] = mn.as_dict()
        self.wallet.db.put_protx_mns(stored_mns)
        self.wallet.save_db()

    @with_manager_lock
    def update_mn(self, alias, new_mn):
        new_alias = new_mn.alias
        if not new_alias:
            raise ProTxManagerExc('Masternode alias can not be empty')
        if len(new_alias) > 32:
            raise ProTxManagerExc('Masternode alias can not be longer '
                                  'than 32 characters')
        if alias not in self.mns.keys():
            raise ProTxManagerExc('Masternode with alias %s does not exists' %
                                  alias)
        self.mns[alias] = new_mn
        self.save(with_lock=False)

    @with_manager_lock
    def add_mn(self, mn):
        alias = mn.alias
        if not alias:
            raise ProTxManagerExc('Masternode alias can not be empty')
        if len(alias) > 32:
            raise ProTxManagerExc('Masternode alias can not be longer '
                                  'than 32 characters')
        if alias in self.mns.keys():
            raise ProTxManagerExc('Masternode with alias %s already exists' %
                                  alias)
        self.mns[alias] = mn
        self.save(with_lock=False)

    @with_manager_lock
    def remove_mn(self, alias):
        if alias not in self.mns.keys():
            raise ProTxManagerExc('Masternode with alias %s does not exists' %
                                  alias)
        del self.mns[alias]
        self.save(with_lock=False)

    @with_manager_lock
    def rename_mn(self, alias, new_alias):
        if not new_alias:
            raise ProTxManagerExc('Masternode alias can not be empty')
        if len(new_alias) > 32:
            raise ProTxManagerExc('Masternode alias can not be longer '
                                  'than 32 characters')
        if alias not in self.mns.keys():
            raise ProTxManagerExc('Masternode with alias %s does not exists' %
                                  alias)
        if new_alias in self.mns.keys():
            raise ProTxManagerExc('Masternode with alias %s already exists' %
                                  new_alias)
        mn = self.mns[alias]
        mn.alias = new_alias
        self.mns[new_alias] = mn
        del self.mns[alias]
        self.save(with_lock=False)

    def prepare_pro_reg_tx(self, alias):
        '''Prepare and return ProRegTx from ProTxMN alias'''
        mn = self.mns.get('%s' % alias)
        if not mn:
            raise ProRegTxExc('Masternode alias %s not found' % alias)

        coll_hash_is_null = mn.collateral.hash_is_null

        if mn.protx_hash:
            raise ProRegTxExc('Masternode already registered')

        if not mn.is_owned:
            raise ProRegTxExc('You not owner of this masternode')

        if not len(mn.collateral.hash) == 32:
            raise ProRegTxExc('Collateral hash is not set')

        if not mn.collateral.index >= 0:
            if not coll_hash_is_null:
                raise ProRegTxExc('Collateral index is not set')

        if not mn.owner_addr:
            raise ProRegTxExc('Owner address is not set')

        if not mn.pubkey_operator:
            raise ProRegTxExc('PubKeyOperator is not set')

        if not mn.voting_addr:
            raise ProRegTxExc('Voting address is not set')

        if not 0 <= mn.op_reward <= 10000:
            raise ProRegTxExc('operatorReward not in range 0-10000')

        if not mn.payout_address:
            raise ProRegTxExc('Payout address is not set')

        if not is_b58_address(mn.payout_address):
            raise ProRegTxExc('Payout address is not address')

        scriptPayout = bfh(address_to_script(mn.payout_address))
        KeyIdOwner = b58_address_to_hash160(mn.owner_addr)[1]
        PubKeyOperator = bfh(mn.pubkey_operator)
        KeyIdVoting = b58_address_to_hash160(mn.voting_addr)[1]
        payloadSig = b'' if coll_hash_is_null else b'\x00'*65

        tx = DashProRegTx(1, mn.type, mn.mode, mn.collateral, mn.service.ip,
                          mn.service.port, KeyIdOwner, PubKeyOperator,
                          KeyIdVoting, mn.op_reward, scriptPayout,
                          b'\x00'*32, payloadSig)

        if not coll_hash_is_null:
            tx.payload_sig_msg_part = ('%s|%s|%s|%s|' %
                                       (mn.payout_address,
                                        mn.collateral.index,
                                        mn.owner_addr,
                                        mn.voting_addr))
        return tx

    def prepare_pro_up_srv_tx(self, mn):
        '''Prepare and return ProUpServTx from ProTxMN alias'''
        if not mn.protx_hash:
            raise ProRegTxExc('Masternode has no proTxHash')

        if not mn.is_operated:
            raise ProRegTxExc('You are not operator of this masternode')

        if not mn.service.ip:
            raise ProRegTxExc('Service IP address is not set')

        if mn.op_payout_address:
            if not is_b58_address(mn.op_payout_address):
                raise ProRegTxExc('Operator payout address is not address')
            scriptOpPayout = bfh(address_to_script(mn.op_payout_address))
        else:
            scriptOpPayout = b''

        tx = DashProUpServTx(1, bfh(mn.protx_hash)[::-1],
                             mn.service.ip, mn.service.port,
                             scriptOpPayout, b'\x00'*32, b'\x00'*96)
        return tx

    def prepare_pro_up_reg_tx(self, mn):
        '''Prepare and return ProUpRegTx from ProTxMN alias'''
        if not mn.protx_hash:
            raise ProRegTxExc('Masternode has no proTxHash')

        if not mn.is_owned:
            raise ProRegTxExc('You not owner of this masternode')

        if not mn.pubkey_operator:
            raise ProRegTxExc('PubKeyOperator is not set')

        if not mn.voting_addr:
            raise ProRegTxExc('Voting address is not set')

        if not mn.payout_address:
            raise ProRegTxExc('Payout address is not set')

        if not is_b58_address(mn.payout_address):
            raise ProRegTxExc('Payout address is not address')

        scriptPayout = bfh(address_to_script(mn.payout_address))
        PubKeyOperator = bfh(mn.pubkey_operator)
        KeyIdVoting = b58_address_to_hash160(mn.voting_addr)[1]

        tx = DashProUpRegTx(1, bfh(mn.protx_hash)[::-1], mn.mode,
                            PubKeyOperator, KeyIdVoting, scriptPayout,
                            b'\x00'*32, b'\x00'*65)
        return tx

    def prepare_pro_up_rev_tx(self, alias, reason):
        '''Prepare and return ProUpRevTx from ProTxMN alias'''
        mn = self.mns.get('%s' % alias)
        if not mn:
            raise ProRegTxExc('Masternode alias %s not found' % alias)

        if not mn.protx_hash:
            raise ProRegTxExc('Masternode has no proTxHash')

        if not mn.is_operated:
            raise ProRegTxExc('You are not operator of this masternode')

        if not isinstance(reason, int) or not 0 <= reason <= 3:
            raise ProRegTxExc('Reason must be integer in range 0-3')

        tx = DashProUpRevTx(1, bfh(mn.protx_hash)[::-1], reason,
                            b'\x00'*32, b'\x00'*96)
        return tx

    def update_mn_from_sml_entry(self, mn, sml_entry):
        changed_aliases = set()
        if not mn.is_operated:
            if (mn.service.ip != str_ip(sml_entry.ipAddress)
                    or mn.service.port != sml_entry.port):
                mn.service = ProTxService(str_ip(sml_entry.ipAddress),
                                          sml_entry.port)
                changed_aliases.add(mn.alias)
        return changed_aliases

    def update_mns_from_protx_list(self, *, diff_hashes=None):
        no_protx_has_mns = []
        mn_list = self.network.mn_list
        changed_aliases = set()
        for mn in self.mns.values():
            protx_hash = mn.protx_hash
            if not protx_hash:
                no_protx_has_mns.append(mn)
                continue
            if diff_hashes and protx_hash not in diff_hashes:
                continue
            sml_entry = mn_list.protx_mns.get(protx_hash)
            if sml_entry:
                changed_aliases |= self.update_mn_from_sml_entry(mn, sml_entry)
        if no_protx_has_mns:
            for protx_hash, sml_entry in mn_list.protx_mns.items():
                if diff_hashes and protx_hash not in diff_hashes:
                    continue
                pubkey_operator = bh2u(sml_entry.pubKeyOperator)
                for mn in no_protx_has_mns:
                    if mn.pubkey_operator != pubkey_operator:
                        continue
                    changed_aliases.add(mn.alias)
                    mn.protx_hash = bh2u(sml_entry.proRegTxHash[::-1])
                    self.update_mn_from_sml_entry(mn, sml_entry)
        for alias in changed_aliases:
            self.alias_updated = alias
            self.notify('manager-alias-updated')
        if changed_aliases:
            self.save()

    def on_mn_list_diff_updated(self, key, diff_update):
        if diff_update['state'] == MNList.DIP3_DISABLED:
            return
        diff_hashes = diff_update['diff_hashes']
        if diff_hashes:
            self.update_mns_from_protx_list(diff_hashes=diff_hashes)

    def find_owner_addr_use(self, addr, skip_alias=None):
        for mn in self.mns.values():
            alias = mn.alias
            if skip_alias and skip_alias == alias:
                continue
            if addr == mn.owner_addr:
                return alias

    def find_service_use(self, service, skip_alias=None,
                         ignore_wallet=False, ignore_mn_list=False):
        if not service.ip or ignore_wallet and ignore_mn_list:
            return
        skipped_mn = None
        for mn in self.mns.values():
            alias = mn.alias
            if skip_alias and skip_alias == alias:
                skipped_mn = mn
                continue
            if str(service) == str(mn.service) and not ignore_wallet:
                return alias
        if ignore_mn_list:
            return
        for sml_entry in self.network.mn_list.protx_mns.values():
            if (service.ip == str_ip(sml_entry.ipAddress)
                    and service.port == sml_entry.port):
                protx_hash = bh2u(sml_entry.proRegTxHash[::-1])
                if skipped_mn and skipped_mn.protx_hash == protx_hash:
                    continue
                return True

    def find_bls_pub_use(self, bls_pub, skip_alias=None,
                         ignore_wallet=False, ignore_mn_list=False):
        if not bls_pub or ignore_wallet and ignore_mn_list:
            return
        skipped_mn = None
        for mn in self.mns.values():
            alias = mn.alias
            if skip_alias and skip_alias == alias:
                skipped_mn = mn
                continue
            if bls_pub == mn.pubkey_operator and not ignore_wallet:
                return alias
        if ignore_mn_list:
            return
        for sml_entry in self.network.mn_list.protx_mns.values():
            if bls_pub == bh2u(sml_entry.pubKeyOperator):
                protx_hash = bh2u(sml_entry.proRegTxHash[::-1])
                if skipped_mn and skipped_mn.protx_hash == protx_hash:
                    continue
                return True
