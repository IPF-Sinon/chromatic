#pragma once
#include <string>
#include <vector>

namespace chromatic::js {

struct InstructionInfo {
  std::string mnemonic;
  std::string opStr;
  int size;
  std::string bytes;   // hex
  std::string address; // hex
  std::vector<int> groups;
  std::vector<int> regsRead;
  std::vector<int> regsWrite;
};

struct InstructionAnalysis {
  bool isBranch;
  bool isCall;
  bool isRelative;
  std::string target; // hex
  bool isPcRelative;
  int size;
};

struct NativeDisassembler {
  /// Disassemble one instruction at address.
  static InstructionInfo disassembleOne(const std::string &address);

  /// Disassemble `count` instructions starting at address.
  static std::vector<InstructionInfo> disassemble(const std::string &address, int count);

  /// Analyze instruction for control flow.
  static InstructionAnalysis analyzeInstruction(const std::string &address);
};
} // namespace chromatic::js
