import { NativeExceptionHandler } from 'chromatic';
import { NativePointer } from './native-pointer';

export interface ExceptionDetails {
  type: string;
  address: NativePointer;
}

export interface ExceptionListenerId {
  remove(): void;
}

/**
 * ExceptionHandler — opt-in global exception/signal handler.
 *
 * Installs POSIX signal handlers (SIGSEGV, SIGBUS, SIGTRAP, SIGILL) or
 * Windows VEH to catch hardware exceptions without crashing.
 */
export const ExceptionHandler = {
  /**
   * Enable the global exception handler. Idempotent.
   */
  enable(): void {
    NativeExceptionHandler.enable();
  },

  /**
   * Disable the global exception handler. Restores original signal handlers.
   */
  disable(): void {
    NativeExceptionHandler.disable();
  },

  /**
   * Whether the exception handler is currently enabled.
   */
  get isEnabled(): boolean {
    return NativeExceptionHandler.isEnabled();
  },

  /**
   * Register a callback for a specific exception type.
   *
   * @param type - "access_violation"|"breakpoint"|"single_step"|"bus_error"|"illegal_instruction"
   * @param callback - Called with exception details when an exception of the given type occurs.
   * @returns An object with a `remove()` method to unregister the callback.
   */
  addCallback(type: string, callback: (details: ExceptionDetails) => void): ExceptionListenerId {
    const id = NativeExceptionHandler.addCallback(type, (exType: string, faultAddr: string) => {
      try {
        callback({ type: exType, address: new NativePointer(faultAddr) });
      } catch (e) {
        // Swallow
      }
    });
    return {
      remove() {
        NativeExceptionHandler.removeCallback(id);
      }
    };
  },

  /**
   * Remove all registered callbacks.
   */
  removeAllCallbacks(): void {
    NativeExceptionHandler.removeAllCallbacks();
  },
};
