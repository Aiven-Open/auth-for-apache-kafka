/** Copyright (c) 2019 Aiven, Helsinki, Finland. https://aiven.io/
 */

package io.aiven.kafka.auth.utils;

import org.apache.kafka.common.utils.Time;

/**
 * This timer class' code is taken from Kafka 2.1.0 to compensate
 * the lack of it in earlier versions.
 */
public class Timer {
  private final Time time;
  private long currentTimeMs;
  private long deadlineMs;

  Timer(Time time, long timeoutMs) {
    this.time = time;
    update();
    reset(timeoutMs);
  }

  public boolean isExpired() {
    return currentTimeMs >= deadlineMs;
  }

  /**
   * Reset the timer to the specific timeout. This will use the underlying {@link Time}
   * implementation to update the current cached time in milliseconds and it will set a new timer
   * deadline.
   *
   * @param timeoutMs The new timeout in milliseconds
   */
  public void updateAndReset(long timeoutMs) {
    update();
    reset(timeoutMs);
  }

  /**
   * Reset the timer using a new timeout. Note that this does not update the cached current time
   * in milliseconds, so it typically must be accompanied with a separate call to {@link #update()}.
   * Typically, you can just use {@link #updateAndReset(long)}.
   *
   * @param timeoutMs The new timeout in milliseconds
   */
  public void reset(long timeoutMs) {
    if (timeoutMs < 0) {
      throw new IllegalArgumentException("Invalid negative timeout " + timeoutMs);
    }

    if (currentTimeMs > Long.MAX_VALUE - timeoutMs) {
      this.deadlineMs = Long.MAX_VALUE;
    } else {
      this.deadlineMs = currentTimeMs + timeoutMs;
    }
  }

  /**
   * Use the underlying {@link Time} implementation to update the current cached time. If
   * the underlying time returns a value which is smaller than the current cached time,
   * the update will be ignored.
   */
  public void update() {
    update(time.milliseconds());
  }

  /**
   * Update the cached current time to a specific value. In some contexts, the caller may already
   * have an accurate time, so this avoids unnecessary calls to system time.
   *
   * <p>Note that if the updated current time is smaller than the cached time, then the update
   * is ignored.
   *
   * @param currentTimeMs The current time in milliseconds to cache
   */
  public void update(long currentTimeMs) {
    this.currentTimeMs = Math.max(currentTimeMs, this.currentTimeMs);
  }
}
