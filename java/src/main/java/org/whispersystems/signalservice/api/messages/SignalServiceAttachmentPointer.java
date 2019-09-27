/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.signalservice.api.messages;

import org.whispersystems.libsignal.util.guava.Optional;
import org.whispersystems.signalservice.api.SignalServiceMessageReceiver;

/**
 * Represents a received SignalServiceAttachment "handle."  This
 * is a pointer to the actual attachment content, which needs to be
 * retrieved using {@link SignalServiceMessageReceiver#retrieveAttachment(SignalServiceAttachmentPointer, java.io.File)}
 *
 * @author Moxie Marlinspike
 */
public class SignalServiceAttachmentPointer extends SignalServiceAttachment {

  private final String id;
  private final byte[]            key;
  private final Optional<String>  relay;
  private final Optional<Integer> size;
  private final Optional<byte[]>  preview;

  public SignalServiceAttachmentPointer(String id, String contentType, byte[] key, String relay) {
    this(id, contentType, key, relay, Optional.<Integer>absent(), Optional.<byte[]>absent());
  }

  public SignalServiceAttachmentPointer(String id, String contentType, byte[] key, String relay,
                                        Optional<Integer> size, Optional<byte[]> preview)
  {
    super(contentType);
    this.id      = id;
    this.key     = key;
    this.relay   = Optional.fromNullable(relay);
    this.size    = size;
    this.preview = preview;
  }

  public String getId() {
    return id;
  }

  public byte[] getKey() {
    return key;
  }

  @Override
  public boolean isStream() {
    return false;
  }

  @Override
  public boolean isPointer() {
    return true;
  }

  public Optional<String> getRelay() {
    return relay;
  }

  public Optional<Integer> getSize() {
    return size;
  }

  public Optional<byte[]> getPreview() {
    return preview;
  }
}
