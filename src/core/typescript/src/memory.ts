import { NativeMemory } from 'chromatic';
import { NativePointer } from './native-pointer';
import type { NativePointerValue } from './types';

/**
 * Memory — Frida-compatible memory operations.
 */
export const Memory = {
  /**
   * Allocate `size` bytes of memory with rwx permissions.
   */
  alloc(size: number): NativePointer {
    const addr = NativeMemory.allocateMemory(size);
    return new NativePointer(addr);
  },

  /**
   * Allocate and write a UTF-8 string.
   */
  allocUtf8String(str: string): NativePointer {
    const encoded: number[] = [];
    for (let i = 0; i < str.length; i++) {
      let cp = str.codePointAt(i)!;
      if (cp < 0x80) {
        encoded.push(cp);
      } else if (cp < 0x800) {
        encoded.push(0xC0 | (cp >> 6), 0x80 | (cp & 0x3F));
      } else if (cp < 0x10000) {
        encoded.push(0xE0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3F), 0x80 | (cp & 0x3F));
      } else {
        encoded.push(0xF0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3F), 0x80 | ((cp >> 6) & 0x3F), 0x80 | (cp & 0x3F));
        i++;
      }
    }
    encoded.push(0); // null terminator

    const ptr = Memory.alloc(encoded.length);
    ptr.writeByteArray(encoded);
    return ptr;
  },

  /**
   * Change memory protection.
   */
  protect(address: NativePointerValue, size: number, protection: string): boolean {
    try {
      const ptr = new NativePointer(address);
      NativeMemory.protectMemory(ptr.toString(), size, protection);
      return true;
    } catch {
      return false;
    }
  },

  /**
   * Copy `size` bytes from `src` to `dst`.
   */
  copy(dst: NativePointerValue, src: NativePointerValue, size: number): void {
    const d = new NativePointer(dst);
    const s = new NativePointer(src);
    NativeMemory.copyMemory(d.toString(), s.toString(), size);
  },

  /**
   * Synchronous memory scan. Returns array of matching addresses.
   */
  scanSync(address: NativePointerValue, size: number, pattern: string): { address: NativePointer; size: number }[] {
    const ptr = new NativePointer(address);
    const resultJson = NativeMemory.scanMemory(ptr.toString(), size, pattern);
    const addresses: string[] = JSON.parse(resultJson);
    return addresses.map(a => ({
      address: new NativePointer(a),
      size: pattern.trim().split(/\s+/).length
    }));
  },

  /**
   * Patch code at address with new bytes (handles permission + icache flush).
   */
  patchCode(address: NativePointerValue, size: number, apply: (code: NativePointer) => void): void {
    const ptr = new NativePointer(address);
    // Allocate temporary writable buffer
    const buf = Memory.alloc(size);
    // Copy original code
    Memory.copy(buf, ptr, size);
    // Let user modify the buffer
    apply(buf);
    // Patch the hex
    const hex = NativeMemory.readMemory(buf.toString(), size);
    NativeMemory.patchCode(ptr.toString(), hex);
  },

  /**
   * Free previously allocated memory.
   */
  free(address: NativePointerValue, size: number): void {
    const ptr = new NativePointer(address);
    NativeMemory.freeMemory(ptr.toString(), size);
  }
};
