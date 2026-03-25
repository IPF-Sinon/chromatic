#include "native_disassembler.h"
#include <capstone/capstone.h>
#include <cstdint>
#include <sstream>
#include <stdexcept>

namespace {

uint64_t parseHexAddr(const std::string &s) {
  return std::stoull(s, nullptr, 16);
}

std::string toHexAddr(uint64_t addr) {
  std::ostringstream oss;
  oss << "0x" << std::hex << addr;
  return oss.str();
}

std::string bytesToHex(const uint8_t *data, size_t len) {
  std::string result;
  static const char hexchars[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    if (i > 0)
      result += ' ';
    result.push_back(hexchars[(data[i] >> 4) & 0xF]);
    result.push_back(hexchars[data[i] & 0xF]);
  }
  return result;
}

cs_arch getArch() {
#ifdef CHROMATIC_ARM64
  return CS_ARCH_ARM64;
#else
  return CS_ARCH_X86;
#endif
}

cs_mode getMode() {
#ifdef CHROMATIC_ARM64
  return CS_MODE_ARM;
#else
  return CS_MODE_64;
#endif
}

struct CapstoneHandle {
  csh handle;
  CapstoneHandle() {
    if (cs_open(getArch(), getMode(), &handle) != CS_ERR_OK)
      throw std::runtime_error("Failed to initialize Capstone");
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
  }
  ~CapstoneHandle() { cs_close(&handle); }
};

thread_local CapstoneHandle cs_handle;

chromatic::js::InstructionInfo insnToInfo(cs_insn *insn) {
  chromatic::js::InstructionInfo info;
  info.mnemonic = insn->mnemonic;
  info.opStr = insn->op_str;
  info.size = static_cast<int>(insn->size);
  info.bytes = bytesToHex(insn->bytes, insn->size);
  info.address = toHexAddr(insn->address);

  if (insn->detail) {
    for (uint8_t i = 0; i < insn->detail->groups_count; i++) {
      info.groups.push_back(static_cast<int>(insn->detail->groups[i]));
    }
    for (uint8_t i = 0; i < insn->detail->regs_read_count; i++) {
      info.regsRead.push_back(static_cast<int>(insn->detail->regs_read[i]));
    }
    for (uint8_t i = 0; i < insn->detail->regs_write_count; i++) {
      info.regsWrite.push_back(static_cast<int>(insn->detail->regs_write[i]));
    }
  }

  return info;
}

} // namespace

namespace chromatic::js {

InstructionInfo NativeDisassembler::disassembleOne(const std::string &address) {
  uint64_t addr = parseHexAddr(address);
  auto code = reinterpret_cast<const uint8_t *>(addr);

  cs_insn *insn;
  size_t count = cs_disasm(cs_handle.handle, code, 16, addr, 1, &insn);
  if (count == 0)
    return InstructionInfo{"", "", 0, "", toHexAddr(addr), {}, {}, {}};

  auto result = insnToInfo(&insn[0]);
  cs_free(insn, count);
  return result;
}

std::vector<InstructionInfo> NativeDisassembler::disassemble(const std::string &address,
                                            int count) {
  uint64_t addr = parseHexAddr(address);
  auto code = reinterpret_cast<const uint8_t *>(addr);

  cs_insn *insn;
  size_t maxBytes = static_cast<size_t>(count) * 16;
  size_t disasmCount =
      cs_disasm(cs_handle.handle, code, maxBytes, addr, count, &insn);

  std::vector<InstructionInfo> result;
  for (size_t i = 0; i < disasmCount; i++) {
    result.push_back(insnToInfo(&insn[i]));
  }

  if (disasmCount > 0)
    cs_free(insn, disasmCount);
  return result;
}

InstructionAnalysis
NativeDisassembler::analyzeInstruction(const std::string &address) {
  uint64_t addr = parseHexAddr(address);
  auto code = reinterpret_cast<const uint8_t *>(addr);

  cs_insn *insn;
  size_t count = cs_disasm(cs_handle.handle, code, 16, addr, 1, &insn);
  if (count == 0)
    return InstructionAnalysis{false, false, false, "0x0", false, 0};

  bool isBranch = false;
  bool isCall = false;
  bool isRelative = false;
  bool isPcRelative = false;
  uint64_t target = 0;

  if (insn->detail) {
    for (uint8_t i = 0; i < insn->detail->groups_count; i++) {
      if (insn->detail->groups[i] == CS_GRP_JUMP)
        isBranch = true;
      if (insn->detail->groups[i] == CS_GRP_CALL)
        isCall = true;
      if (insn->detail->groups[i] == CS_GRP_BRANCH_RELATIVE)
        isRelative = true;
    }

#ifdef CHROMATIC_ARM64
    auto &arm64 = insn->detail->arm64;
    for (uint8_t i = 0; i < arm64.op_count; i++) {
      if (arm64.operands[i].type == ARM64_OP_IMM) {
        target = static_cast<uint64_t>(arm64.operands[i].imm);
        isPcRelative = true;
        break;
      }
    }
#else
    auto &x86 = insn->detail->x86;
    for (uint8_t i = 0; i < x86.op_count; i++) {
      if (x86.operands[i].type == X86_OP_IMM) {
        target = static_cast<uint64_t>(x86.operands[i].imm);
        isPcRelative = true;
        break;
      } else if (x86.operands[i].type == X86_OP_MEM &&
                 x86.operands[i].mem.base == X86_REG_RIP) {
        target = addr + insn->size + x86.operands[i].mem.disp;
        isPcRelative = true;
        break;
      }
    }
#endif
  }

  int size = insn->size;
  cs_free(insn, count);

  return InstructionAnalysis{isBranch, isCall, isRelative, toHexAddr(target), isPcRelative, size};
}

} // namespace chromatic::js
