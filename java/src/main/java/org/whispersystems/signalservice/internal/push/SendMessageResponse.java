package org.whispersystems.signalservice.internal.push;

public class SendMessageResponse {

  private boolean needsSync;
  private int status;

  public SendMessageResponse() {}

  public SendMessageResponse(boolean needsSync, int status) {
    this.needsSync = needsSync;
    this.status = status;
  }

  public boolean getNeedsSync() {
    return needsSync;
  }

  public int getStatus() {
    return status;
  }
}
