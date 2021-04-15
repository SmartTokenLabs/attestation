package com.alphawallet.attestation.core;


import org.apache.logging.log4j.Logger;

public class ExceptionUtil {
  /**
   * Cast a CheckedException as an unchecked one.
   *
   * @param logger Logger to log the exception
   * @param message Specific and new message
   * @param cause to cast
   * @param <T>       the type of the Throwable
   * @return this method will never return a Throwable instance, it will just throw it.
   * @throws T the throwable as an unchecked throwable
   */
  @SuppressWarnings("unchecked")
  public static <T extends Throwable> RuntimeException makeRuntimeException(Logger logger, String message, Throwable cause) throws T {
    logger.fatal(message, cause);
    throw (T) new RuntimeException(message, cause); // rely on vacuous cast
  }

  @SuppressWarnings("unchecked")
  public static <T extends Throwable> T throwException(Logger logger, T cause) throws T {
    logger.fatal(cause.getMessage(), cause);
    throw (T) cause;
  }

}
