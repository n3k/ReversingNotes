#https://zairon.wordpress.com/2008/02/15/idc-script-and-stack-frame-variables-length/

import idautils
import idaapi
import idc
import struct

from collections import defaultdict
import operator

g_vars = {} # Global variables

EFI_BOOT_SERVICES_LocateProtocol = 0x140
EFI_SMM_SYSTEM_TABLE_SmmLocateProtocol = 0xD0


GUID_TABLE = {
'EFI_MM_SW_DISPATCH_PROTOCOL_GUID': 'GUID(0x18a3c6dc,0x5eea,0x48c8,0xa1,0xc1,0xb5,0x33,0x89,0xf9,0x89,0x99)',
'EFI_SMM_VARIABLE_PROTOCOL_GUID': 'GUID(0xed32d533,0x99e6,0x4209,0x9c,0xc0,0x2d,0x72,0xcd,0xd9,0x98,0xa7)',
'EFI_ACPI_TABLE_PROTOCOL_GUID': 'GUID(0xffe06bdd,0x6107,0x46a6,0x7b,0xb2,0x5a,0x9c,0x7e,0xc5,0x27,0x5c)',
'EFI_LOADED_IMAGE_PROTOCOL_GUID': 'GUID(0x5b1b31a1,0x9562,0x11d2,0x8e,0x3f,0x0,0xa0,0xc9,0x69,0x72,0x3b)',
'EFI_FIRMWARE_VOLUME2_PROTOCOL_GUID': 'GUID(0x220e73b6,0x6bdb,0x4413,0x84,0x5,0xb9,0x74,0xb1,0x8,0x61,0x9a)',
'EFI_MM_CPU_PROTOCOL_GUID': 'GUID(0xeb346b97,0x975f,0x4a9f,0x8b,0x22,0xf8,0xe9,0x2b,0xb3,0xd5,0x69)',
'EFI_MM_BASE_PROTOCOL_GUID': 'GUID(0xf4ccbfb7,0xf6e0,0x47fd,0x9d,0xd4,0x10,0xa8,0xf1,0x50,0xc1,0x91)',
'EFI_ATA_PASS_THRU_PROTOCOL_GUID': 'GUID(0x1d3de7f0,0x807,0x424f,0xaa,0x69,0x11,0xa5,0x4e,0x19,0xa4,0x6f)',
'H19SgxSmmInterfaceGuid': 'GUID(0x468907b3,0x174b,0x4617,0xa0,0x23,0x8f,0x7c,0xe6,0x0,0x36,0x48)',
'H19PlatformServiceSmmInterfaceGuid': 'GUID(0x5a3a840d,0x2432,0x4a59,0xa9,0xef,0x6d,0xa0,0x95,0xe,0x37,0x54)',
'AutoPowerOnSmmInterfaceGuid': 'GUID(0x5a72a74f,0x4842,0x44d8,0x94,0xd8,0xa3,0x0e,0x5,0xa9,0x85,0x4e)',
'H19HddPasswordInterfaceGuid': 'GUID(0xafa92c3,0x9d71,0x47cb,0x89,0x24,0x21,0xb6,0xc2,0x45,0x7c,0x0)',
'H19MeUpdateSmmInterfaceGuid': 'GUID(0x1e686608,0x4a96,0x49f8,0xa7,0xd2,0x43,0xc5,0x6,0x92,0x83,0x55)',
'H19ServiceBodySmmInterfaceGuid': 'GUID(0x9156c0ad,0x57ca,0x42c7,0xbc,0xd3,0xe5,0xd8,0x2d,0xe0,0x5f,0x34)',
'BiosGuardServicesInterfaceGuid': 'GUID(0x17565311,0x4b71,0x4340,0x88,0xaa,0xdc,0x9f,0x44,0x22,0xe5,0x3a)',
'OFCSmmDriverInterfaceGuid': 'GUID(0xa618df46,0x1b05,0x463e,0xa6,0xfd,0xf4,0x3b,0x9b,0xfb,0x27,0xcc)',
'H19RecordLogSmmInterfaceGuid': 'GUID(0x25bbabe3,0xf185,0x461b,0x80,0xc0,0x58,0x3d,0xb8,0xc0,0xa4,0x41)',
'AspmOverrideDxeInterfaceGuid': 'GUID(0x4cd150e9,0x16b,0x4e54,0xbd,0x0,0x5c,0x86,0xeb,0xe6,0x37,0xd6)',
'EFI_LEGACY_BIOS_PROTOCOL_GUID': 'GUID(0xdb9a1e3d,0x45cb,0x4abb,0x85,0x3b,0xe5,0x38,0x7f,0xdb,0x2e,0x2d)',
'IhisiServicesSmmInterface': 'GUID(0x6c23a1ef,0x2cb7,0x4a60,0x8f,0x8c,0x8,0xa3,0xde,0x8d,0x7a,0xcf)',
'Int15ServiceSmmInterface': 'GUID(0x1fa493a8,0xb360,0x4205,0xb8,0xfe,0xcc,0x83,0xbc,0x57,0xb7,0x3a)',
'PchSmiDispatcherInterface1': 'GUID(0x6906e93b,0x603b,0x4a0f,0x86,0x92,0x83,0x20,0x4,0xaa,0xf2,0xdb)',
'PchSmiDispatcherInterface2': 'GUID(0xb3c14ff3,0xbae8,0x456c,0x86,0x31,0x27,0xfe,0xc,0xeb,0x34,0xc)',
'PchSmiDispatcherInterface3': 'GUID(0x58dc368d,0x7bfa,0x4e77,0xab,0xbc,0xe,0x29,0x41,0x8d,0xf9,0x30)',
'PchSmiDispatcherInterface4': 'GUID(0x514d2afd,0x2096,0x4283,0x9d,0xa6,0x70,0xc,0xd2,0x7d,0xc7,0xa5)',
'EFI_MM_IO_TRAP_DISPATCH_PROTOCOL_GUID': 'GUID(0x58dc368d,0x7bfa,0x4e77,0xab,0xbc,0xe,0x29,0x41,0x8d,0xf9,0x30)',
'EFI_RUNTIME_CRYPT_PROTOCOL_GUID': 'GUID(0xe1475e0c,0x1746,0x4802,0x86,0x2e,0x1,0x1c,0x2c,0x2d,0x9d,0x86)',
'EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL_GUID': 'GUID(0x52c78312,0x8edc,0x4233,0x98,0xf2,0x1a,0x1a,0xa5,0xe3,0x88,0xa5)',
'EFI_SMM_SW_DISPATCH_PROTOCOL_GUID': 'GUID(0xe541b773,0xdd11,0x420c,0xb0,0x26,0xdf,0x99,0x36,0x53,0xf8,0xbf)',
'EFI_DRIVER_BINDING_PROTOCOL_GUID':'GUID(0x18a031ab,0xb443,0x4d1a,0xa5,0xc0,0xc,0x9,0x26,0x1e,0x9f,0x71)',
'EFI_PCD_PROTOCOL_GUID':'GUID(0x13a3f0f6,0x264a,0x3ef0,0xf2,0xe0,0xde,0xc5,0x12,0x34,0x2f,0x34)',
'EFI_GLOBAL_NVS_AREA_PROTOCOL_GUID':'GUID(0x74e1e48,0x8132,0x47a1,0x8c,0x2c,0x3f,0x14,0xad,0x9a,0x66,0xdc)',
'EFI_MM_GPI_DISPATCH_PROTOCOL_GUID': 'GUID(0x25566b03,0xb577,0x4cbf,0x95,0x8c,0xed,0x66,0x3e,0xa2,0x43,0x80)',
'EFI_MM_POWER_BUTTON_DISPATCH_PROTOCOL_GUID':'GUID(0x1b1183fa,0x1823,0x46a7,0x88,0x72,0x9c,0x57,0x87,0x55,0x40,0x9d)',
'PCD_PROTOCOL_GUID':'GUID(0x11b34006,0xd85b,0x4d0a,0xa2,0x90,0xd5,0xa5,0x71,0x31,0xe,0xf7)',
'EFI_ACPI_SUPPORT_GUID':'GUID(0xdbff9d55,0x89b7,0x46da,0xbd,0xdf,0x67,0x7d,0x3d,0xc0,0x24,0x1d)',
}


def print_guid(guid):
    data = "GUID("
    part1 = struct.unpack("<I", guid[0:4])[0]
    data += "{:#08x},".format(part1)
    part2 = struct.unpack("<H", guid[4:6])[0]
    data += "{:#04x},".format(part2)
    part3 = struct.unpack("<H", guid[6:8])[0]
    data += "{:#04x},".format(part3)
    data += ",".join(["{:#02x}".format(ord(_)) for _ in guid[8:]])
    data += ")"
    return data



def get_Tinfo_from_name(name):
    target_idx = 0
    for idx in range(1, idc.GetMaxLocalType()):
        if name in idc.GetLocalTypeName(idx):
            target_idx = idx
            break
    if target_idx != 0:
        #idc.GetLocalType(target_idx,0)
        return idc.GetLocalTinfo(target_idx)
    return None

def assign_struct_to_address(address, struct_name):
    idc.ApplyType(address, get_Tinfo_from_name(struct_name))
    struct_id = idaapi.get_struc_id(struct_name)
    if struct_id != 0xffffffffffffffff:
        struct_size = idaapi.get_struc_size(struct_id)
        for i in range(struct_size):
            idc.MakeUnkn(address+i, 0)
        return idaapi.doStruct(address, struct_size, struct_id)
    return False

def find_function_arg(addr, mnemonic, operand, idx_operand):
    """
    The function looks backwards to find an specific argument
    :param addr: the address from which to start looking backwards
    :param mnemonic: the instruction mnemonic that we're looking
    :param operand: an operand to compare
    :param idx_operand: the operand idx --> mov ebx, eax -> ebx = idx0; eax = idx1
    :return: the address where the argument is being set
    """
    for _ in range(20): # looks up to 20 instructions behind
        addr = idc.PrevHead(addr)
        if idc.GetMnem(addr) == mnemonic and idc.GetOpnd(addr, idx_operand) == operand:
            return addr
    return None

def find_function_arg_with_operand_value(addr, mnemonic, register, value, idx_operand):
    """
    00000000000167FC mov     [rsp+20h], rax
    idc.GetOperandValue(0x167FC, 0) ==> 0x20
    """

    for _ in range(20): # looks up to 20 instructions behind
        addr = idc.PrevHead(addr)
        if idc.GetMnem(addr) == mnemonic and register in idc.GetOpnd(addr, idx_operand)\
                and idc.GetOperandValue(addr, idx_operand) == value:
            return addr
    return None


def find_next_operator_usage(addr, register, mnemonic, idx_operand):
    """
    Search for the usage of a given register from <addr> in the following ten instructions
    """
    curr_addr = addr
    for _ in range(10):
        curr_addr = idc.NextHead(curr_addr)
        if idc.GetMnem(curr_addr) == mnemonic and register in idc.GetOpnd(addr, idx_operand):
            return curr_addr
    return None


def find_callbacks_through_immediate(mnemonic, operand, val):
    result = []
    addr = idc.MinEA()
    for i in range(10):
        addr, operand_ = idc.FindImmediate(addr, idc.SEARCH_DOWN|idc.SEARCH_NEXT, val)
        if addr != idc.BADADDR:
            #print hex(addr), idc.GetDisasm(addr), "Operand ", operand_
            if operand_ == operand and idc.GetMnem(addr) == mnemonic:
                result.append(addr)
                #print addr
        else:
            break
    return result


def list_xref_to_indirect_callback(function_offset):
    calls_to_pfn_list = []
    call_pfns = find_callbacks_through_immediate("call", 0, function_offset)
    if call_pfns != None:
        calls_to_pfn_list.extend(call_pfns)
    return calls_to_pfn_list


def find_efi_boot_services_table():
    xrefs_to_LocateProtocol = list_xref_to_indirect_callback(EFI_BOOT_SERVICES_LocateProtocol)
    score_decision_dict = defaultdict(int)
    # Find where EFI_BOOT_SERVICES table is
    for xref in xrefs_to_LocateProtocol:
        # call qword ptr [rax+140h]
        call_args = idc.GetOpnd(xref, 0).split(" ")[-1].split("+") # ['[rax', '140h]']
        if len(call_args) != 2:
            continue
        ind_call_reg = call_args[0][1:] # rax
        # we're looking for something like :::   mov     rax, cs:qword_1CF0
        mov_gbs_ea = find_function_arg(xref, "mov", ind_call_reg, 0)
        potential_gbs = idc.GetOperandValue(mov_gbs_ea, 1)
        score_decision_dict[potential_gbs] += 1

    gBS = max(score_decision_dict.iteritems(), key=operator.itemgetter(1))[0]
    return gBS


def find_efi_smm_system_table():
    xrefs_to_LocateProtocol = list_xref_to_indirect_callback(EFI_SMM_SYSTEM_TABLE_SmmLocateProtocol)
    score_decision_dict = defaultdict(int)
    # Find where EFI_SMM_SYSTEM_TABLE table is
    for xref in xrefs_to_LocateProtocol:
        # call qword ptr [rax+D0h]
        call_args = idc.GetOpnd(xref, 0).split(" ")[-1].split("+") # ['[rax', 'D0h]']
        if len(call_args) != 2:
            continue
        ind_call_reg = call_args[0][1:] # rax
        # we're looking for something like :::   mov     rax, cs:qword_1CF0
        mov_gsmst_ea = find_function_arg(xref, "mov", ind_call_reg, 0)
        potential_gsmst = idc.GetOperandValue(mov_gsmst_ea, 1)
        score_decision_dict[potential_gsmst] += 1

    gSmst = max(score_decision_dict.iteritems(), key=operator.itemgetter(1))[0]
    return gSmst


def assign_names_based_on_table(table_ea, struct_name, cb=None):
    for xref in idautils.XrefsTo(table_ea):
        register = idc.GetOpnd(xref.frm, 0)
        if type(register) == str:
            call_addr = find_next_operator_usage(xref.frm, register, "call", 0)
            if call_addr != None:
                idc.OpStroffEx(call_addr,0, (idaapi.get_struc_id(struct_name)),0)
                if cb:
                    print hex(call_addr)
                    cb(call_addr)

##############################################################################

def load_types_into_idb():
    header_path = idautils.GetIdbDir()
    idaapi.idc_parse_types("".join([header_path, "behemoth.h"]), idc.PT_FILE)
    for idx in range(1, idc.GetMaxLocalType()):
        print(idx, idc.GetLocalTypeName(idx))
        idc.Til2Idb(idx, idc.GetLocalTypeName(idx))

##############################################################################


##############################################################################

def set_protocol_struct_argument(addr):
    lea_protocol_guid = find_function_arg(addr, "lea", "rcx", 0)
    if lea_protocol_guid:
        protocol_guid = idc.GetOperandValue(lea_protocol_guid, 1)
        assign_struct_to_address(protocol_guid, "GUID")
        guid_bytes = idc.GetManyBytes(protocol_guid, 0x10)
        data = print_guid(guid_bytes)
        protocol_name = ""
        for k, v in GUID_TABLE.items():
            if v == data:
                protocol_name = k
        if protocol_name != "":
            idc.MakeName(protocol_guid, protocol_name)


idaapi.set_compiler_id(0x01)
load_types_into_idb()

gBS = find_efi_boot_services_table()
idc.MakeName(gBS, 'g_BootServices')
assign_names_based_on_table(gBS, "EFI_BOOT_SERVICES", cb=set_protocol_struct_argument)

#gSmst = find_efi_smm_system_table()


