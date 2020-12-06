package org.whispersystems.signalservice.internal.websocket;

import org.whispersystems.libsignal.logging.Log;
import org.whispersystems.signalservice.api.push.TrustStore;
import org.whispersystems.signalservice.api.util.CredentialsProvider;
import org.whispersystems.signalservice.internal.util.BlacklistingTrustManager;
import org.whispersystems.signalservice.internal.util.Util;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.WebSocket;
import okhttp3.WebSocketListener;
import okio.Buffer;
import okio.BufferedSource;
import okio.ByteString;

public class OkHttpClientWrapper extends WebSocketListener {

  private static final String TAG = OkHttpClientWrapper.class.getSimpleName();

  private final String                 uri;
  private final TrustStore             trustStore;
  private final CredentialsProvider    credentialsProvider;
  private final WebSocketEventListener listener;
  private final String                 userAgent;

  private WebSocket webSocket;
  private boolean   closed;
  private boolean   connected;

  public OkHttpClientWrapper(String uri, TrustStore trustStore,
                             CredentialsProvider credentialsProvider,
                             String userAgent,
                             WebSocketEventListener listener)
  {
    Log.w(TAG, "Connecting to: " + uri);

    this.uri                 = uri;
    this.trustStore          = trustStore;
    this.credentialsProvider = credentialsProvider;
    this.userAgent           = userAgent;
    this.listener            = listener;
  }

  public void connect(final int timeout, final TimeUnit timeUnit) {
    new Thread() {
      @Override
      public void run() {
        int attempt = 0;

        while ((webSocket = newSocket(timeout, timeUnit)) != null) {
          Util.sleep(Math.min(++attempt * 200, TimeUnit.SECONDS.toMillis(15)));
        }
      }
    }.start();
  }

  public synchronized void disconnect() {
    Log.w(TAG, "Calling disconnect()...");
      closed = true;
      if (webSocket != null && connected) {
        webSocket.close(1000, "OK");
      }
  }

  public void sendMessage(byte[] message) {
    webSocket.send(ByteString.of(message));
  }

  @Override
  public synchronized void onMessage(WebSocket webSocket, ByteString payload) {
    listener.onMessage(payload.toByteArray());
  }

  @Override
  public synchronized void onClosed(WebSocket webSocket, int code, String reason) {
    Log.w(TAG, String.format("onClose(%d, %s)", code, reason));
    listener.onClose();
  }

  @Override
  public void onFailure(WebSocket webSocket, Throwable t, Response r) {
      Log.w(TAG, t);
      listener.onClose();
  }

  private synchronized WebSocket newSocket(int timeout, TimeUnit unit) {
    if (closed) return null;

    String       filledUri    = String.format(uri, credentialsProvider.getUser(), credentialsProvider.getPassword());
      CertificatePinner certPinner = new CertificatePinner.Builder()
              .add("*.kalimdor.network",
                      "sha256/VtOB0C/9LihdefUvKEOHAB7f+IZgTvW+wfN9AzZ4tVg=")
              .build();
    OkHttpClient okHttpClient = new OkHttpClient.Builder()
            .certificatePinner(certPinner)
            .sslSocketFactory(createTlsSocketFactory(trustStore))
            .readTimeout(timeout, unit)
            .connectTimeout(timeout, unit)
            .build();

    Request.Builder requestBuilder = new Request.Builder().url(filledUri);

    if (userAgent != null) {
      requestBuilder.addHeader("X-Signal-Agent", userAgent);
    }

    return okHttpClient.newWebSocket(requestBuilder.build(), this);
  }

  private SSLSocketFactory createTlsSocketFactory(TrustStore trustStore) {
    try {
      SSLContext context = SSLContext.getInstance("TLS");
      if (trustStore != null) {
        context.init(null, BlacklistingTrustManager.createFor(trustStore), null);
      } else {
        context.init(null, null, null);
      }

      return context.getSocketFactory();
    } catch (NoSuchAlgorithmException | KeyManagementException e) {
      throw new AssertionError(e);
    }
  }

    @Override
    public void onOpen(WebSocket webSocket, Response response) {
        super.onOpen(webSocket, response);
        connected = true;
    }
}
