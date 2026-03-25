/**
 * Int64 / UInt64 — boxed 64-bit integers for Frida API compatibility.
 */

export class Int64 {
  private _value: bigint;

  constructor(value: string | number | bigint | Int64 = 0) {
    if (value instanceof Int64) {
      this._value = value._value;
    } else {
      this._value = BigInt(value);
    }
  }

  add(rhs: Int64 | number | string | bigint): Int64 {
    return new Int64(this._value + BigInt(rhs instanceof Int64 ? rhs._value : rhs));
  }

  sub(rhs: Int64 | number | string | bigint): Int64 {
    return new Int64(this._value - BigInt(rhs instanceof Int64 ? rhs._value : rhs));
  }

  and(rhs: Int64 | number | string | bigint): Int64 {
    return new Int64(this._value & BigInt(rhs instanceof Int64 ? rhs._value : rhs));
  }

  or(rhs: Int64 | number | string | bigint): Int64 {
    return new Int64(this._value | BigInt(rhs instanceof Int64 ? rhs._value : rhs));
  }

  xor(rhs: Int64 | number | string | bigint): Int64 {
    return new Int64(this._value ^ BigInt(rhs instanceof Int64 ? rhs._value : rhs));
  }

  shr(n: number): Int64 {
    return new Int64(this._value >> BigInt(n));
  }

  shl(n: number): Int64 {
    return new Int64(this._value << BigInt(n));
  }

  not(): Int64 {
    return new Int64(~this._value);
  }

  equals(rhs: Int64 | number | string | bigint): boolean {
    return this._value === BigInt(rhs instanceof Int64 ? rhs._value : rhs);
  }

  compare(rhs: Int64 | number | string | bigint): number {
    const other = BigInt(rhs instanceof Int64 ? rhs._value : rhs);
    if (this._value < other) return -1;
    if (this._value > other) return 1;
    return 0;
  }

  toNumber(): number {
    return Number(this._value);
  }

  toString(radix: number = 10): string {
    return this._value.toString(radix);
  }

  toJSON(): string {
    return this._value.toString();
  }

  valueOf(): bigint {
    return this._value;
  }
}

export class UInt64 {
  private _value: bigint;

  constructor(value: string | number | bigint | UInt64 = 0) {
    if (value instanceof UInt64) {
      this._value = value._value;
    } else {
      this._value = BigInt.asUintN(64, BigInt(value));
    }
  }

  add(rhs: UInt64 | number | string | bigint): UInt64 {
    return new UInt64(this._value + BigInt(rhs instanceof UInt64 ? rhs._value : rhs));
  }

  sub(rhs: UInt64 | number | string | bigint): UInt64 {
    return new UInt64(this._value - BigInt(rhs instanceof UInt64 ? rhs._value : rhs));
  }

  and(rhs: UInt64 | number | string | bigint): UInt64 {
    return new UInt64(this._value & BigInt(rhs instanceof UInt64 ? rhs._value : rhs));
  }

  or(rhs: UInt64 | number | string | bigint): UInt64 {
    return new UInt64(this._value | BigInt(rhs instanceof UInt64 ? rhs._value : rhs));
  }

  xor(rhs: UInt64 | number | string | bigint): UInt64 {
    return new UInt64(this._value ^ BigInt(rhs instanceof UInt64 ? rhs._value : rhs));
  }

  shr(n: number): UInt64 {
    return new UInt64(this._value >> BigInt(n));
  }

  shl(n: number): UInt64 {
    return new UInt64(this._value << BigInt(n));
  }

  not(): UInt64 {
    return new UInt64(BigInt.asUintN(64, ~this._value));
  }

  equals(rhs: UInt64 | number | string | bigint): boolean {
    return this._value === BigInt.asUintN(64, BigInt(rhs instanceof UInt64 ? rhs._value : rhs));
  }

  compare(rhs: UInt64 | number | string | bigint): number {
    const other = BigInt.asUintN(64, BigInt(rhs instanceof UInt64 ? rhs._value : rhs));
    if (this._value < other) return -1;
    if (this._value > other) return 1;
    return 0;
  }

  toNumber(): number {
    return Number(this._value);
  }

  toString(radix: number = 10): string {
    return this._value.toString(radix);
  }

  toJSON(): string {
    return this._value.toString();
  }

  valueOf(): bigint {
    return this._value;
  }
}
