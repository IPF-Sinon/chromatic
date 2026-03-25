import { NativeDisassembler } from 'chromatic';
import { NativePointer } from './native-pointer';
import type { NativePointerValue, InstructionInfo } from './types';

/**
 * Instruction — disassemble and parse native instructions.
 * Now backed by struct-returning C++ bindings (no JSON.parse needed).
 */
export const Instruction = {
  /**
   * Parse a single instruction at the given address.
   */
  parse(target: NativePointerValue): InstructionInfo {
    const ptr = new NativePointer(target);
    const raw = NativeDisassembler.disassembleOne(ptr.toString());
    return {
      address: new NativePointer(raw.address),
      mnemonic: raw.mnemonic || '',
      opStr: raw.opStr || '',
      size: raw.size || 0,
      bytes: raw.bytes || '',
      groups: raw.groups || [],
      regsRead: raw.regsRead || [],
      regsWrite: raw.regsWrite || []
    };
  },

  /**
   * Disassemble multiple instructions.
   */
  disassemble(target: NativePointerValue, count: number): InstructionInfo[] {
    const ptr = new NativePointer(target);
    const rawArr = NativeDisassembler.disassemble(ptr.toString(), count);
    return rawArr.map(r => ({
      address: new NativePointer(r.address),
      mnemonic: r.mnemonic || '',
      opStr: r.opStr || '',
      size: r.size || 0,
      bytes: r.bytes || '',
      groups: r.groups || [],
      regsRead: r.regsRead || [],
      regsWrite: r.regsWrite || []
    }));
  },

  /**
   * Analyze a single instruction for control flow properties.
   */
  analyze(target: NativePointerValue): {
    isBranch: boolean;
    isCall: boolean;
    isRelative: boolean;
    target: NativePointer;
    isPcRelative: boolean;
    size: number;
  } {
    const ptr = new NativePointer(target);
    const raw = NativeDisassembler.analyzeInstruction(ptr.toString());
    return {
      isBranch: raw.isBranch,
      isCall: raw.isCall,
      isRelative: raw.isRelative,
      target: new NativePointer(raw.target),
      isPcRelative: raw.isPcRelative,
      size: raw.size
    };
  }
};
