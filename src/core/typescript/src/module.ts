import { NativeProcess } from 'chromatic';
import { NativePointer } from './native-pointer';
import type { ModuleInfo, ExportInfo, NativePointerValue } from './types';

/**
 * Module — Frida-compatible module operations.
 * Now backed by struct-returning C++ bindings (no JSON.parse needed).
 */
export class Module {
  name: string;
  base: NativePointer;
  size: number;
  path: string;

  constructor(info: ModuleInfo) {
    this.name = info.name;
    this.base = new NativePointer(info.base);
    this.size = info.size;
    this.path = info.path;
  }

  /**
   * Find an export by name within this module.
   */
  findExportByName(exportName: string): NativePointer | null {
    return Module.findExportByName(this.name, exportName);
  }

  /**
   * Enumerate exports of this module.
   */
  enumerateExports(): ExportInfo[] {
    return Module.enumerateExports(this.name);
  }

  // ---- Static methods ----

  /**
   * Find an export by name. If moduleName is null, searches all modules.
   */
  static findExportByName(moduleName: string | null, exportName: string): NativePointer | null {
    const addr = NativeProcess.findExportByName(moduleName || '', exportName);
    if (addr === '0x0') return null;
    return new NativePointer(addr);
  }

  /**
   * Find the base address of a module by name.
   */
  static findBaseAddress(moduleName: string): NativePointer | null {
    const m = NativeProcess.findModuleByName(moduleName);
    if (!m) return null;
    return new NativePointer(m.base);
  }

  /**
   * Enumerate all loaded modules.
   */
  static enumerateModules(): Module[] {
    const modules = NativeProcess.enumerateModules();
    return modules.map(m => new Module({
      name: m.name,
      base: new NativePointer(m.base),
      size: m.size,
      path: m.path
    }));
  }

  /**
   * Enumerate exports of a specific module.
   */
  static enumerateExports(moduleName: string): ExportInfo[] {
    const exports = NativeProcess.enumerateExports(moduleName);
    return exports.map(e => ({
      type: e.type,
      name: e.name,
      address: new NativePointer(e.address)
    }));
  }

  /**
   * Get module by name.
   */
  static load(moduleName: string): Module | null {
    const m = NativeProcess.findModuleByName(moduleName);
    if (!m) return null;
    return new Module({
      name: m.name,
      base: new NativePointer(m.base),
      size: m.size,
      path: m.path
    });
  }
}
