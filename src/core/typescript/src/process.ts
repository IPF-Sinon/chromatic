import { NativeProcess as NP } from 'chromatic';
import { NativePointer } from './native-pointer';
import type { ModuleInfo, RangeInfo } from './types';

/**
 * Process — provides info about the current process.
 * Now backed by struct-returning C++ bindings (no JSON.parse needed).
 */
export const Process = {
  get arch(): string {
    return NP.getArchitecture();
  },

  get platform(): string {
    return NP.getPlatform();
  },

  get pointerSize(): number {
    return NP.getPointerSize();
  },

  get pageSize(): number {
    return NP.getPageSize();
  },

  get id(): number {
    return NP.getProcessId();
  },

  getCurrentThreadId(): number {
    const hex = NP.getCurrentThreadId();
    return Number(BigInt(hex));
  },

  enumerateModules(): ModuleInfo[] {
    const modules = NP.enumerateModules();
    return modules.map(m => ({
      name: m.name,
      base: new NativePointer(m.base),
      size: m.size,
      path: m.path
    }));
  },

  enumerateRanges(protection: string): RangeInfo[] {
    const ranges = NP.enumerateRanges(protection);
    return ranges.map(r => ({
      base: new NativePointer(r.base),
      size: r.size,
      protection: r.protection,
      file: r.filePath ? { path: r.filePath } : undefined
    }));
  },

  findModuleByAddress(address: NativePointer | string): ModuleInfo | null {
    const ptr = new NativePointer(address);
    const m = NP.findModuleByAddress(ptr.toString());
    if (!m) return null;
    return {
      name: m.name,
      base: new NativePointer(m.base),
      size: m.size,
      path: m.path
    };
  },

  findModuleByName(name: string): ModuleInfo | null {
    const m = NP.findModuleByName(name);
    if (!m) return null;
    return {
      name: m.name,
      base: new NativePointer(m.base),
      size: m.size,
      path: m.path
    };
  }
};
