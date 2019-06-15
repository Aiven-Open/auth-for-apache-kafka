/** Copyright (c) 2019 Aiven, Helsinki, Finland. https://aiven.io/
 */

package io.aiven.kafka.auth.utils;

import org.apache.kafka.common.utils.Time;

/**
 * This wrapper for Kafka {@link Time} class is needed to compensate
 * the lack of {@code Timer} in Kafka before 2.1.0.
 */
public class TimeWithTimer {
  private final Time time;

  public TimeWithTimer(Time time) {
    this.time = time;
  }

  public Timer timer(long timeoutMs) {
    return new Timer(time, timeoutMs);
  }
}
