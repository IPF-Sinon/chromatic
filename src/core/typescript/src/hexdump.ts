import { NativeMemory } from 'chromatic';
import { NativePointer } from './native-pointer';
import type { NativePointerValue } from './types';

/**
 * hexdump — produce a hex dump of memory at the given address.
 * Compatible with Frida's hexdump() function.
 */
export function hexdump(
  target: NativePointerValue | ArrayBuffer,
  options?: { offset?: number; length?: number; header?: boolean; ansi?: boolean }
): string {
  const offset = options?.offset ?? 0;
  const length = options?.length ?? 256;
  const header = options?.header ?? true;
  const ansi = options?.ansi ?? false;

  let bytes: number[];
  let baseAddr: bigint;

  if (target instanceof ArrayBuffer) {
    const view = new Uint8Array(target);
    bytes = [];
    for (let i = offset; i < Math.min(view.length, offset + length); i++) {
      bytes.push(view[i]);
    }
    baseAddr = BigInt(offset);
  } else {
    const ptr = new NativePointer(target);
    const addr = ptr.add(offset);
    const hex = NativeMemory.safeReadMemory(addr.toString(), length);
    if (!hex) return '(inaccessible)';
    bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
      bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    baseAddr = BigInt(addr.toString());
  }

  const lines: string[] = [];

  if (header) {
    let hdr = '           ';
    for (let i = 0; i < 16; i++) {
      hdr += ' ' + i.toString(16).padStart(2, '0');
    }
    hdr += '  ';
    for (let i = 0; i < 16; i++) {
      hdr += i.toString(16);
    }
    lines.push(hdr);
  }

  for (let i = 0; i < bytes.length; i += 16) {
    const addr = (baseAddr + BigInt(i)).toString(16).padStart(10, '0');
    let hexPart = '';
    let asciiPart = '';

    for (let j = 0; j < 16; j++) {
      if (i + j < bytes.length) {
        hexPart += ' ' + bytes[i + j].toString(16).padStart(2, '0');
        const ch = bytes[i + j];
        asciiPart += (ch >= 0x20 && ch <= 0x7E) ? String.fromCharCode(ch) : '.';
      } else {
        hexPart += '   ';
        asciiPart += ' ';
      }
    }

    lines.push(`0x${addr} ${hexPart}  ${asciiPart}`);
  }

  return lines.join('\n');
}
