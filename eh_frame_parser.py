
'''
    GNU_EH_FRAME function extractor IDA plugin.
    by Ignacio Sanmillan (ulexec)

    This plugin is based on Ryan O'Neill (@ryan_elfmaster) technique to parse GNU_EH_FRAME program header as
    a means to find function addresses and sizes without the need of any symbolic information.

    Initial POC can be found in Ryan's site at: http://www.bitlackeys.org/#eh_frame
'''


from struct import pack
from struct import unpack
from struct import unpack_from

from PyQt5 import QtCore
from PyQt5 import QtGui
from PyQt5 import QtWidgets
from idc import GetManyBytes
from idaapi import PluginForm
from elftools.elf.elffile import ELFFile
from elftools.elf.descriptions import describe_p_type


'''
    DWARF EH_FRAME encoding definitions
'''
EI_CLASSNONE = 0
EI_CLASS32 = 1
EI_CLASS64 = 2
DW_EH_PE_absptr	= 0x00
DW_EH_PE_omit	= 0xff
DW_EH_PE_uleb128 = 0x01
DW_EH_PE_udata2	= 0x02
DW_EH_PE_udata4	= 0x03
DW_EH_PE_udata8	= 0x04
DW_EH_PE_sleb128 = 0x09
DW_EH_PE_sdata2	= 0x0a
DW_EH_PE_sdata4	= 0x0b
DW_EH_PE_sdata8	= 0x0c
DW_EH_PE_signed	= 0x09
DW_EH_PE_pcrel	= 0x10
DW_EH_PE_indirect = 0x80
DW_EH_PE_textrel = 0x20
DW_EH_PE_datarel = 0x30
DW_EH_PE_funcrel = 0x40
DW_EH_PE_aligned = 0x50


def get_address_in_decimal(hex_address):
    return int(hex_address, 16)


def get_address_in_hex(address):
    hex_address = hex(address)
    return hex_address[:-1]


class BlockTable0(QtWidgets.QTableWidget):
    def __init__(self, parent=None):
        QtWidgets.QTableWidget.__init__(self, parent)
        self._fields = [
            {
                'key': 'function_address',
                'name': 'Function Address',
                'address': lambda x: get_address_in_decimal(x),
                'format': lambda x: get_address_in_hex(x)
            },
            {
                'key': 'function_size',
                'name': 'Function Size',
                'address': lambda x: idc.LocByName(x)
            },
        ]

    def contextMenuEvent(self, event):
        menu = QtWidgets.QMenu(self)
        copyAction = menu.addAction('Copy')

        action = menu.exec_(self.mapToGlobal(event.pos()))

        if action == copyAction:
            QtWidgets.QApplication.clipboard().setText(str(map(lambda x: x.text(), self.selectedItems())))

    def _handle_double_click(self, row, column):
        if 'address' not in self._fields[column]:
            column = 2

        address = self._fields[column]['address'](self.item(row, column).text())

        idc.Jump(address)

    def _sort_column(self, column):
        if self._fields[column].get('desc'):
            self._fields[column]['desc'] = False
            self.sortByColumn(column, QtCore.Qt.DescendingOrder)
        else:
            self._fields[column]['desc'] = True
            self.sortByColumn(column, QtCore.Qt.AscendingOrder)

    def _initial_table(self):
        self.setRowCount(0)
        self.setColumnCount(len(self._fields))

        for index, field in enumerate(self._fields):
            self.setHorizontalHeaderItem(index, QtWidgets.QTableWidgetItem(field['name']))

        self.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.cellDoubleClicked.connect(self._handle_double_click)
        self.horizontalHeader().sectionClicked.connect(self._sort_column)

    def _add_block_result(self, block):
        row_count = self.rowCount()
        self.setRowCount(row_count + 1)

        for index, field in enumerate(self._fields):
            item = QtWidgets.QTableWidgetItem()
            value = block.get(field['key'], '')

            if not value:
                value = ''
            else:
                value = field['format'](value) if 'format' in field else value

            item.setData(QtCore.Qt.DisplayRole, value)
            self.setItem(row_count, index, item)

    def create_block_table(self, block_map):
        self._initial_table()

        for block in block_map:
            self._add_block_result(block)

    def filter(self, text):
        for row_index in range(self.rowCount()):
            hide_row = True
            for column_index in range(self.columnCount()):
                value = self.item(row_index, column_index)

                if not value:
                    continue

                if text in value.text().lower():
                    hide_row = False
                    break

            self.setRowHidden(row_index, hide_row)


class BlockForm0(PluginForm):
    def __init__(self, block_map):
        super(BlockForm0, self).__init__()
        self._block_map = block_map

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.block_table = BlockTable0()
        self.block_table.create_block_table(self._block_map)

        self.PopulateForm()

        QtWidgets.QShortcut(QtGui.QKeySequence('Ctrl+F'), PluginForm.FormToPyQtWidget(form), self._filter)

    def OnClose(self, form):
        pass

    def PopulateForm(self):
        self.vboxLayout = QtWidgets.QVBoxLayout()
        self.gridLayout = QtWidgets.QGridLayout()

        self.gridLayout.addWidget(self.block_table, 0, 0)
        self.vboxLayout.addLayout(self.gridLayout)

        self.parent.setLayout(self.vboxLayout)

    def _filter(self):
        text = idc.AskStr('', 'text')
        text = text.lower() if text else ''
        self.block_table.filter(text)


'''
    Unsigned LEB decoding needed for some GNU_EH_FRAME Table entries
'''
def get_uleb128(content):
    value = i = tmp = 0
    for i in range(0, 5):
        tmp = ord(content[i]) & 0x7f
        value = tmp << (i * 7) | value
        if (ord(content[i]) & 0x80) != 0x80:
            break
    if i == 4 and (tmp & 0xf0) != 0:
        print("parsing error")
        return -1
    return value


'''
    Signed LEB decoding needed for some GNU_EH_FRAME segment Table entries
'''
def get_sleb128(content):
    mask = [0xffffff80, 0xffffc000, 0xffe00000, 0xf0000000, 0]
    bitmask = [0x40, 0x40, 0x40, 0x40, 0x8]
    value = i = tmp = 0
    for i in range(0, 5):
        tmp = ord(content[i]) & 0x7f
        value = tmp << (i * 7) | value
        if (ord(content[i]) & 0x80) != 0x80:
            if bitmask[i] & tmp:
                value |= mask[i]
            break
    if i == 4 and (tmp & 0xf0) != 0:
        print("parsing error")
        return -1
    buffer = pack("I", value)
    value, = unpack("i", buffer)

    return value


'''
    Class denoting .eh_frame_hdr encoded byte instances
'''
class EncodedByte:
    def __init__(self, byte):
        if len(byte) != 1:
            raise ValueError()
        self.encoding = ord(byte[0]) & 0xf0
        self.value = ord(byte[0]) & 0x7


'''
    Class denoting GNU_EH_FRAME Segment relevant fields before FDE Entry Table
'''
class EhFrameHdr:
    def __init__(self, phdr,  elf):
        self._elf = elf
        self._phdr = phdr
        self.vaddr = self._phdr['p_vaddr']
        self.fde_table_vaddr = self.vaddr + 12
        self.file_bytes = GetManyBytes(self._phdr['p_vaddr'], self._phdr['p_filesz'])
        (self.version,
         self.eh_frame_ptr_enc,
         self.fde_count_enc,
         self.table_enc,
         self.eh_frame_ptr,
         self.fde_count) = unpack_from('4c2I', self.file_bytes, 0)

    '''
        Function is dedicated to decode a given FDE Entry or a given GNU_EH_FRAME Header Field
        This function will return a Tuple containing the virtual address and size of the function
        or just the value of a given FDE Entry or encoded GNU_EH_FRAME header field respectively.
    '''
    def decode_pointer(self, encoding_byte, target_entry, pc=None):
        encoding_byte = EncodedByte(encoding_byte)
        value_size = fmt = result = None
        elf_class = self._elf.header['e_ident']['EI_CLASS']

        if encoding_byte.value == DW_EH_PE_omit or encoding_byte.encoding == DW_EH_PE_omit:
            return
        elif encoding_byte.value == DW_EH_PE_uleb128:
            return get_uleb128(target_entry)
        elif encoding_byte.value == DW_EH_PE_sleb128:
            return get_sleb128(target_entry)
        else:
            if encoding_byte.value == DW_EH_PE_absptr:
                value_size = 8 if elf_class == EI_CLASS64 else 4
                fmt = "<q" if elf_class == EI_CLASS64 else "<i"
            elif encoding_byte.value == DW_EH_PE_udata2 or encoding_byte.value == DW_EH_PE_sdata2:
                value_size = 2
                fmt = "<b"
            elif encoding_byte.value == DW_EH_PE_udata4 or encoding_byte.value == DW_EH_PE_sdata4:
                value_size = 4
                fmt = "<i"
            elif encoding_byte.value == DW_EH_PE_udata8 or encoding_byte.value == DW_EH_PE_sdata8:
                value_size = 8
                fmt = "<q"

            if not value_size and not fmt:
                return

            if encoding_byte.encoding == DW_EH_PE_pcrel:
                result = unpack(fmt, GetManyBytes(pc + target_entry, value_size))[0]
            elif encoding_byte.encoding == DW_EH_PE_absptr:
                result = target_entry
            elif encoding_byte.encoding == DW_EH_PE_datarel:
                if target_entry > 0x7fffffff:
                    target_entry -= 0x100000000
                function_vaddr = self._phdr['p_vaddr'] + target_entry
                function_size = \
                    unpack(fmt, GetManyBytes(self.fde_table_vaddr + pc, value_size))[0]
                result = (function_vaddr, function_size)
            elif encoding_byte.encoding == DW_EH_PE_textrel or encoding_byte.encoding == DW_EH_PE_funcrel:
                # These encoding schemes are not implemented. I have read they are not longer supported
                return
        if encoding_byte.encoding & DW_EH_PE_indirect:
            result = unpack(fmt, GetManyBYtes(result, value_size))[0]

        return result


class EHFrameParser(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = ''
    help = ''
    wanted_name = 'GNU_EH_FRAME function parser'
    wanted_hotkey = 'Ctrl-Alt-0'

    def init(self):
        return idaapi.PLUGIN_KEEP

    def term(self):
        return None

    def run(self, args):
        file_path = idaapi.get_input_file_path()

        if not file_path:
            print('Input file path was not found')
            return

        try:
            fd = open(file_path, "rb")
            elf = ELFFile(fd)
        except Exception as x:
            print(x)
            return

        eh_frame_phdr = next(
            (segment for segment in elf.iter_segments() if describe_p_type(segment['p_type']) == 'GNU_EH_FRAME'),
            None)

        if not eh_frame_phdr:
            print("[-] Executable was not compiled with exception unwinding information")
            return

        eh_frame_hdr_data = EhFrameHdr(eh_frame_phdr, elf)
        fde_count = eh_frame_hdr_data.decode_pointer(eh_frame_hdr_data.fde_count_enc, eh_frame_hdr_data.fde_count, pc=eh_frame_phdr['p_vaddr'] + 8)
        block_map = []

        for i in range(0, fde_count):
            (initial_loc, fde_entry_offset) = unpack("2I", GetManyBytes(eh_frame_hdr_data.fde_table_vaddr + 8 * i, 8))
            (function_vaddr, function_size) = eh_frame_hdr_data.decode_pointer(eh_frame_hdr_data.table_enc, initial_loc, fde_entry_offset)
            block_map.append({'function_address': function_vaddr, 'function_size': function_size})
        block_form = BlockForm0(block_map)
        block_form.Show('GNU_EH_FRAME functions')


def PLUGIN_ENTRY():
    return EHFrameParser()