#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
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
import math
from typing import Optional, List, Dict, Sequence, Set
from enum import IntEnum
from functools import partial

from PyQt5.QtCore import (pyqtSignal, Qt, QModelIndex, QVariant,
                          QAbstractItemModel, QItemSelectionModel)
from PyQt5.QtGui import QFont, QBrush, QColor
from PyQt5.QtWidgets import (QAbstractItemView, QHeaderView, QComboBox,
                             QLabel, QMenu)

from electrum_dash.i18n import _
from electrum_dash.transaction import PartialTxInput
from electrum_dash.dash_ps_util import (PSCoinRounds, sort_utxos_by_ps_rounds,
                                        ps_coin_rounds_str)
from electrum_dash.logging import Logger
from electrum_dash.util import profiler, format_time

from .util import MyTreeView, ColorScheme, MONOSPACE_FONT, EnterButton, GetDataThread


SELECTED_TO_SPEND_TOOLTIP = _('Coin selected to be spent')


class PSStateFilter(IntEnum):
    ALL = 0
    PS = 1
    PS_OTHER = 2
    REGULAR = 3

    def ui_text(self) -> str:
        return {
            self.ALL: _('All'),
            self.PS: _('PrivateSend'),
            self.PS_OTHER: _('PS Other coins'),
            self.REGULAR: _('Regular'),
        }[self]


class KeystoreFilter(IntEnum):
    ALL = 0
    PS_KS = 1
    MAIN = 2

    def ui_text(self) -> str:
        return {
            self.ALL: _('All'),
            self.PS_KS: _('PS Keystore'),
            self.MAIN: _('Main'),
        }[self]


class UTXOColumns(IntEnum):
    DATE = 0
    OUTPOINT = 1
    ADDRESS = 2
    LABEL = 3
    AMOUNT = 4
    HEIGHT = 5
    PS_ROUNDS = 6
    KEYSTORE_TYPE = 7


UTXOHeaders = {
    UTXOColumns.DATE: _('Date'),
    UTXOColumns.ADDRESS: _('Address'),
    UTXOColumns.LABEL: _('Label'),
    UTXOColumns.PS_ROUNDS: _('PS Rounds'),
    UTXOColumns.KEYSTORE_TYPE : _('Keystore'),
    UTXOColumns.AMOUNT: _('Amount'),
    UTXOColumns.HEIGHT: _('Height'),
    UTXOColumns.OUTPOINT: _('Output point'),
}


class UTXOModel(QAbstractItemModel, Logger):

    data_ready = pyqtSignal()

    SELECT_ROWS = QItemSelectionModel.Rows | QItemSelectionModel.Select

    SORT_KEYS = {
        UTXOColumns.DATE: lambda x: x['prevout_timestamp'],
        UTXOColumns.ADDRESS: lambda x: x['address'],
        UTXOColumns.LABEL: lambda x: x['label'],
        UTXOColumns.PS_ROUNDS: lambda x: x['ix'],
        UTXOColumns.KEYSTORE_TYPE: lambda x: x['is_ps_ks'],
        UTXOColumns.AMOUNT: lambda x: x['balance'],
        UTXOColumns.HEIGHT: lambda x: x['height'],
        UTXOColumns.OUTPOINT: lambda x: x['outpoint'],
    }

    def __init__(self, parent):
        super(UTXOModel, self).__init__(parent)
        Logger.__init__(self)
        self.parent = parent
        self.wallet = self.parent.wallet
        self.coin_items = list()
        # setup bg thread to get updated data
        self.data_ready.connect(self.on_get_data, Qt.QueuedConnection)
        self.get_data_thread = GetDataThread(self, self.get_coins,
                                             self.data_ready, self)
        self.get_data_thread.start()

    def set_view(self, utxo_list):
        self.view = utxo_list
        self.set_visibility_of_columns()

    def headerData(self, section, orientation, role):
        if role != Qt.DisplayRole:
            return
        return UTXOHeaders[section]

    def flags(self, idx):
        extra_flags = Qt.NoItemFlags
        if idx.column() in self.view.editable_columns:
            extra_flags |= Qt.ItemIsEditable
        return super().flags(idx) | extra_flags

    def columnCount(self, parent: QModelIndex):
        return len(UTXOColumns)

    def rowCount(self, parent: QModelIndex):
        return len(self.coin_items)

    def index(self, row: int, column: int, parent: QModelIndex):
        if not parent.isValid():  # parent is root
            if len(self.coin_items) > row:
                return self.createIndex(row, column, self.coin_items[row])
        return QModelIndex()

    def parent(self, index: QModelIndex):
        return QModelIndex()

    def hasChildren(self, index: QModelIndex):
        return not index.isValid()

    def sort(self, col, order):
        if self.coin_items:
            self.process_changes(self.sorted(self.coin_items, col, order))

    def sorted(self, coin_items, col, order):
        return sorted(coin_items, key=self.SORT_KEYS[col], reverse=order)

    def data(self, index: QModelIndex, role: Qt.ItemDataRole) -> QVariant:
        assert index.isValid()
        col = index.column()
        coin_item = index.internalPointer()
        address = coin_item['address']
        is_frozen_addr = coin_item['is_frozen_addr']
        is_frozen_coin = coin_item['is_frozen_coin']
        height = coin_item['height']
        time_str = ''
        if self.view.config.get('show_utxo_time', False):
            prevout_timestamp = coin_item['prevout_timestamp']
            time_str = (format_time(prevout_timestamp)
                        if prevout_timestamp < math.inf
                        else _('unknown'))
        outpoint = coin_item['outpoint']
        out_short = coin_item['out_short']
        label = coin_item['label']
        balance = coin_item['balance']
        ps_rounds = coin_item['ps_rounds']
        is_ps_ks = coin_item['is_ps_ks']
        if ps_rounds is None:
            ps_rounds = 'N/A'
        else:
            ps_rounds = ps_coin_rounds_str(ps_rounds)
        if (role == self.view.ROLE_CLIPBOARD_DATA
                and col == UTXOColumns.OUTPOINT):
            return QVariant(outpoint)
        elif role == Qt.ToolTipRole:
            if col == UTXOColumns.ADDRESS and is_frozen_addr:
                return QVariant(_('Address is frozen'))
            elif col == UTXOColumns.OUTPOINT and is_frozen_coin:
                return QVariant(f'{outpoint}\n{_("Coin is frozen")}')
            elif outpoint in (self.view._spend_set or set()):
                if col == UTXOColumns.OUTPOINT:
                    return QVariant(f'{outpoint}\n{SELECTED_TO_SPEND_TOOLTIP}')
                else:
                    return QVariant(SELECTED_TO_SPEND_TOOLTIP)
            elif col == UTXOColumns.OUTPOINT:
                return QVariant(outpoint)
        elif role not in (Qt.DisplayRole, Qt.EditRole):
            if role == Qt.TextAlignmentRole:
                if col in [UTXOColumns.DATE, UTXOColumns.AMOUNT,
                           UTXOColumns.HEIGHT, UTXOColumns.PS_ROUNDS,
                           UTXOColumns.KEYSTORE_TYPE]:
                    return QVariant(Qt.AlignRight | Qt.AlignVCenter)
                else:
                    return QVariant(Qt.AlignVCenter)
            elif role == Qt.FontRole:
                return QVariant(QFont(MONOSPACE_FONT))
            elif role == Qt.ForegroundRole:
                if col == UTXOColumns.LABEL:
                    # Green for explicit tx label, red for address label fallback
                    is_tx_label = bool(coin_item.get('label_is_tx', False))
                    color = QColor("#00A000") if is_tx_label else QColor("#DC0000")
                    return QVariant(QBrush(color))
            elif role == Qt.BackgroundRole:
                if col == UTXOColumns.ADDRESS and is_frozen_addr:
                    return QVariant(ColorScheme.BLUE.as_color(True))
                elif col == UTXOColumns.OUTPOINT and is_frozen_coin:
                    return QVariant(ColorScheme.BLUE.as_color(True))
                elif outpoint in (self.view._spend_set or set()):
                    return QVariant(ColorScheme.GREEN.as_color(True))
        elif col == UTXOColumns.DATE:
            return QVariant(time_str)
        elif col == UTXOColumns.OUTPOINT:
            return QVariant(out_short)
        elif col == UTXOColumns.ADDRESS:
            return QVariant(address)
        elif col == UTXOColumns.LABEL:
            return QVariant(label)
        elif col == UTXOColumns.AMOUNT:
            return QVariant(balance)
        elif col == UTXOColumns.HEIGHT:
            return QVariant(height)
        elif col == UTXOColumns.PS_ROUNDS:
            return QVariant(ps_rounds)
        elif col == UTXOColumns.KEYSTORE_TYPE:
            return QVariant(_('PS Keystore') if is_ps_ks else _('Main'))
        else:
            return QVariant()

    @profiler
    def get_coins(self):
        coin_items = []

        show_ps = self.view.show_ps
        show_ps_ks = self.view.show_ps_ks
        w = self.wallet
        if self.view.config.get('show_utxo_time', False):
            get_utxos = partial(w.get_utxos, prevout_timestamp=True)
        else:
            get_utxos = w.get_utxos
        if show_ps == PSStateFilter.ALL:
            utxos = get_utxos(include_ps=True)
        elif show_ps == PSStateFilter.PS:
            utxos = get_utxos(min_rounds=PSCoinRounds.COLLATERAL)
        elif show_ps == PSStateFilter.PS_OTHER:
            utxos = get_utxos(min_rounds=PSCoinRounds.MINUSINF)
            utxos = [c for c in utxos if c.ps_rounds <= PSCoinRounds.OTHER]
        else:  # Regular
            utxos = get_utxos()
        if show_ps_ks == KeystoreFilter.PS_KS:
            utxos = [c for c in utxos if c.is_ps_ks]
        elif show_ps_ks == KeystoreFilter.MAIN:
            utxos = [c for c in utxos if not c.is_ps_ks]
        utxos.sort(key=sort_utxos_by_ps_rounds)
        self.view._maybe_reset_spend_list(utxos)
        self.view._utxo_dict = {}
        for i, utxo in enumerate(utxos):
            address = utxo.address
            value = utxo.value_sats()
            prev_h = utxo.prevout.txid.hex()
            prev_n = utxo.prevout.out_idx
            prevout_timestamp = 0
            if self.view.config.get('show_utxo_time', False):
                prevout_timestamp = utxo.prevout_timestamp
                if not prevout_timestamp:
                    prevout_timestamp = utxo.islock or math.inf
            outpoint = utxo.prevout.to_str()
            self.view._utxo_dict[outpoint] = utxo

            tx_label = w.get_label_for_txid(prev_h)
            if tx_label:
                label = f"TX: {tx_label}"
                label_is_tx = True
            else:
                label = w.get_label(address)
                label_is_tx = False

            coin_items.append({
                'address': address,
                'value': value,
                'prevout_n': prev_n,
                'prevout_hash': prev_h,
                'prevout_timestamp': prevout_timestamp,
                'height': utxo.block_height,
                'coinbase': utxo.is_coinbase_output(),
                'islock': utxo.islock,
                'ps_rounds': utxo.ps_rounds,
                'is_ps_ks': utxo.is_ps_ks,
                # append model fields
                'ix': i,
                'outpoint': outpoint,
                'out_short': f'{prev_h[:16]}...:{prev_n}',
                'is_frozen_addr': w.is_frozen_address(address),
                'is_frozen_coin': w.is_frozen_coin(utxo),
                'label': label,
                'label_is_tx': label_is_tx,
                'balance': self.parent.format_amount(value, whitespaces=True),
            })
        return coin_items

    def set_visibility_of_columns(self):
        col = UTXOColumns.DATE
        if self.view.config.get('show_utxo_time', False):
            self.view.showColumn(col)
        else:
            self.view.hideColumn(col)

    @profiler
    def process_changes(self, coin_items):
        selected = self.view.selectionModel().selectedRows()
        selected_outpoints = []
        for idx in selected:
            selected_outpoints.append(idx.internalPointer()['outpoint'])

        if self.coin_items:
            self.beginRemoveRows(QModelIndex(), 0, len(self.coin_items)-1)
            self.coin_items.clear()
            self.endRemoveRows()

        if coin_items:
            self.beginInsertRows(QModelIndex(), 0, len(coin_items)-1)
            self.coin_items = coin_items[:]
            self.endInsertRows()

        selected_rows = []
        if selected_outpoints:
            for i, coin_item in enumerate(coin_items):
                outpoint = coin_item['outpoint']
                if outpoint in selected_outpoints:
                    selected_rows.append(i)
                    selected_outpoints.remove(outpoint)
                    if not selected_outpoints:
                        break
        if selected_rows:
            for i in selected_rows:
                idx = self.index(i, 0, QModelIndex())
                self.view.selectionModel().select(idx, self.SELECT_ROWS)

    def on_get_data(self):
        self.refresh(self.get_data_thread.res)
        self.set_visibility_of_columns()

    @profiler
    def refresh(self, coin_items, force=False):
        if not force and coin_items == self.coin_items:
            return
        col = self.view.header().sortIndicatorSection()
        order = self.view.header().sortIndicatorOrder()
        self.process_changes(self.sorted(coin_items, col, order))
        self.view.filter()
        self.view.update_coincontrol_status_bar()


class UTXOList(MyTreeView):

    _spend_set: Optional[Set[str]]  # coins selected by the user to spend from
    _utxo_dict: Dict[str, PartialTxInput]  # coin outpoint -> coin

    filter_columns = [UTXOColumns.ADDRESS, UTXOColumns.PS_ROUNDS,
                      UTXOColumns.KEYSTORE_TYPE, UTXOColumns.LABEL,
                      UTXOColumns.OUTPOINT]
    stretch_column = UTXOColumns.LABEL

    def __init__(self, parent, model):
        super().__init__(parent, self.create_menu,
                         stretch_column=self.stretch_column)
        self._spend_set = None
        self._utxo_dict = {}
        self.cm = model
        self.setModel(model)
        self.wallet = self.parent.wallet
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)

        header = self.header()
        header.setDefaultAlignment(Qt.AlignCenter)
        header.setStretchLastSection(False)
        header.setSortIndicator(UTXOColumns.PS_ROUNDS, Qt.AscendingOrder)
        self.setSortingEnabled(True)
        for col in UTXOColumns:
            if col == self.stretch_column:
                header.setSectionResizeMode(col, QHeaderView.Stretch)
            elif col == UTXOColumns.PS_ROUNDS:
                header.setSectionResizeMode(col, QHeaderView.Fixed)
            else:
                header.setSectionResizeMode(col, QHeaderView.ResizeToContents)

        self.show_ps = PSStateFilter.ALL
        self.show_ps_ks = KeystoreFilter.ALL
        self.ps_button = QComboBox(self)
        self.ps_button.currentIndexChanged.connect(self.toggle_ps)
        for ps_state in PSStateFilter.__members__.values():
            self.ps_button.addItem(ps_state.ui_text())
        self.ps_ks_button = QComboBox(self)
        self.ps_ks_button.currentIndexChanged.connect(self.toggle_ps_ks)
        for keystore in KeystoreFilter.__members__.values():
            self.ps_ks_button.addItem(keystore.ui_text())

    def get_toolbar_buttons(self):
        return (QLabel('    %s ' % _("Filter PS Type:")),
                self.ps_button,
                QLabel('    %s ' % _("Keystore:")),
                self.ps_ks_button)

    def on_hide_toolbar(self):
        self.show_ps = PSStateFilter.ALL
        self.show_ps_ks = KeystoreFilter.ALL
        self.update()

    def save_toolbar_state(self, state, config):
        config.set_key('show_toolbar_utxos', state)

    def toggle_ps(self, state):
        if state == self.show_ps:
            return
        self.ps_button.setCurrentIndex(state)
        self.show_ps = PSStateFilter(state)
        self.update()

    def toggle_ps_ks(self, state):
        if state == self.show_ps_ks:
            return
        self.show_ps_ks = KeystoreFilter(state)
        self.update()

    def update(self):
        # not calling maybe_defer_update() as it interferes with coincontrol status bar
        self.cm.get_data_thread.need_update.set()

    def _filter_frozen_coins(self, coins: List[PartialTxInput]) -> List[PartialTxInput]:
        coins = [utxo for utxo in coins
                 if (not self.wallet.is_frozen_address(utxo.address) and
                     not self.wallet.is_frozen_coin(utxo))]
        return coins

    def set_spend_list(self, coins: Optional[List[PartialTxInput]]):
        if coins is not None:
            coins = self._filter_frozen_coins(coins)
            self._spend_set = {utxo.prevout.to_str() for utxo in coins}
            self.parent.set_ps_cb_from_coins(coins)
            self.parent.ps_cb.setEnabled(False)
        else:
            self._spend_set = None
            self.parent.set_ps_cb_from_coins(None)
            self.parent.ps_cb.setEnabled(True)
        self.cm.refresh(self.cm.coin_items, force=True)

    def get_spend_list(self) -> Optional[Sequence[PartialTxInput]]:
        if self._spend_set is None:
            return None
        utxos = [self._utxo_dict[x] for x in self._spend_set]
        return copy.deepcopy(utxos)  # copy so that side-effects don't affect utxo_dict

    def _maybe_reset_spend_list(self, current_wallet_utxos: Sequence[PartialTxInput]) -> None:
        if self._spend_set is None:
            return
        # if we spent one of the selected UTXOs, just reset selection
        utxo_set = {utxo.prevout.to_str() for utxo in current_wallet_utxos}
        if not all([prevout_str in utxo_set for prevout_str in self._spend_set]):
            self._spend_set = None
            self.parent.set_ps_cb_from_coins(None)
            self.parent.ps_cb.setEnabled(True)

    def update_coincontrol_status_bar(self):
        if self._spend_set is not None:
            coins = [self._utxo_dict[x] for x in self._spend_set]
            coins = self._filter_frozen_coins(coins)
            amount = sum(x.value_sats() for x in coins)
            amount_str = self.parent.format_amount_and_units(amount)
            num_outputs_str = _("{} outputs available ({} total)")\
                .format(len(coins), len(self._utxo_dict))
            self.parent.set_coincontrol_msg(_("Coin control active") +
                                            f': {num_outputs_str},'
                                            f' {amount_str}')
        else:
            self.parent.set_coincontrol_msg(None)

    def add_copy_menu(self, menu: QMenu, idx) -> QMenu:
        cc = menu.addMenu(_("Copy"))
        for column in UTXOColumns:
            column_title = UTXOHeaders[column]
            col_idx = idx.sibling(idx.row(), column)
            clipboard_data = self.cm.data(col_idx, self.ROLE_CLIPBOARD_DATA)
            if clipboard_data is None:
                clipboard_data = self.cm.data(col_idx, Qt.DisplayRole)
            clipboard_data = str(clipboard_data.value()).strip()
            cc.addAction(column_title,
                         lambda text=clipboard_data, title=column_title:
                         self.place_text_on_clipboard(text, title=title))
        return cc

    def create_menu(self, position):
        w = self.wallet
        psman = w.psman
        selected = self.selectionModel().selectedRows()
        if not selected:
            return
        menu = QMenu()
        menu.setSeparatorsCollapsible(True)
        coins = []
        for idx in selected:
            if not idx.isValid():
                return
            coin_item = idx.internalPointer()
            if not coin_item:
                return
            outpoint = coin_item['outpoint']
            coins.append(self._utxo_dict[outpoint])
        if len(coins) == 0:
            menu.addAction(_("Spend (select none)"),
                           lambda: self.set_spend_list(coins))
        else:
            menu.addAction(_("Spend"), lambda: self.set_spend_list(coins))

        if len(coins) == 1:
            utxo = coins[0]
            ps_rounds = utxo.ps_rounds
            address = utxo.address
            txid = utxo.prevout.txid.hex()
            outpoint = utxo.prevout.to_str()
            if (ps_rounds is not None
                    and (ps_rounds in [PSCoinRounds.OTHER,
                                       PSCoinRounds.MIX_ORIGIN]
                         or ps_rounds >= 0)):
                coin_val = utxo.value_sats()
                mwin = self.parent
                if coin_val >= psman.min_new_denoms_from_coins_val:

                    def create_new_denoms():
                        mwin.create_new_denoms(coins, self.parent)
                    menu.addAction(_('Create New Denoms'), create_new_denoms)

                elif coin_val >= psman.min_new_collateral_from_coins_val:

                    def create_new_collateral():
                        mwin.create_new_collateral(coins, self.parent)
                    menu.addAction(_('Create New Collateral'),
                                   create_new_collateral)
            # "Details"
            tx = w.db.get_transaction(txid)
            if tx:
                # Prefer None if empty
                # (None hides the Description: field in the window)
                label = w.get_label_for_txid(txid)
                menu.addAction(_("Details"), lambda: self.parent.show_transaction(tx, tx_desc=label))
            # "Copy ..."
            idx = self.indexAt(position)
            if not idx.isValid():
                return
            self.add_copy_menu(menu, idx)

            # "Freeze coin"
            set_frozen_state_c = self.parent.set_frozen_state_of_coins
            if not w.is_frozen_coin(utxo):
                menu.addAction(_("Freeze Coin"),
                               lambda: set_frozen_state_c([utxo], True))
            else:
                menu.addSeparator()
                menu.addAction(_("Coin is frozen"),
                               lambda: None).setEnabled(False)
                menu.addAction(_("Unfreeze Coin"),
                               lambda: set_frozen_state_c([utxo], False))
                menu.addSeparator()
            # "Freeze address"
            set_frozen_state_a = self.parent.set_frozen_state_of_addresses
            if not w.is_frozen_address(address):
                menu.addAction(_("Freeze Address"),
                               lambda: set_frozen_state_a([address], True))
            else:
                menu.addSeparator()
                menu.addAction(_("Address is frozen"),
                               lambda: None).setEnabled(False)
                menu.addAction(_("Unfreeze Address"),
                               lambda: set_frozen_state_a([address], False))
                menu.addSeparator()
        elif len(coins) > 1:  # multiple items selected
            # multiple items selected
            menu.addSeparator()
            addrs = set([utxo.address for utxo in coins])
            is_coin_frozen = [w.is_frozen_coin(utxo) for utxo in coins]
            is_addr_frozen = [w.is_frozen_address(utxo.address)
                              for utxo in coins]

            set_frozen_state_c = self.parent.set_frozen_state_of_coins
            if not all(is_coin_frozen):
                menu.addAction(_("Freeze Coins"),
                               lambda: set_frozen_state_c(coins, True))
            if any(is_coin_frozen):
                menu.addAction(_("Unfreeze Coins"),
                               lambda: set_frozen_state_c(coins, False))

            set_frozen_state_a = self.parent.set_frozen_state_of_addresses
            if not all(is_addr_frozen):
                menu.addAction(_("Freeze Addresses"),
                               lambda: set_frozen_state_a(addrs, True))
            if any(is_addr_frozen):
                menu.addAction(_("Unfreeze Addresses"),
                               lambda: set_frozen_state_a(addrs, False))
        menu.exec_(self.viewport().mapToGlobal(position))

    def hide_rows(self):
        for row in range(len(self.cm.coin_items)):
            if self.current_filter:
                self.hide_row(row)
            else:
                self.setRowHidden(row, QModelIndex(), False)

    def hide_row(self, row):
        model = self.cm
        for column in self.filter_columns:
            idx = model.index(row, column, QModelIndex())
            if idx.isValid():
                txt = model.data(idx, Qt.DisplayRole).value().lower()
                if self.current_filter in txt:
                    self.setRowHidden(row, QModelIndex(), False)
                    return
        self.setRowHidden(row, QModelIndex(), True)
