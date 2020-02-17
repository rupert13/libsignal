package org.whispersystems.signalservice.internal.push;

public class NeedsSync {

  private boolean needsSync;

  public NeedsSync() {}

  public NeedsSync(boolean needsSync, String status) {
    this.needsSync = needsSync;
  }

  public boolean getNeedsSync() {
    return needsSync;
  }
}
