/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.signalservice.internal.push;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;

import org.apache.http.conn.ssl.StrictHostnameVerifier;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.logging.Log;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.util.guava.Optional;
import org.whispersystems.signalservice.api.crypto.AttachmentCipherOutputStream;
import org.whispersystems.signalservice.api.messages.SignalServiceAttachment.ProgressListener;
import org.whispersystems.signalservice.api.messages.multidevice.DeviceInfo;
import org.whispersystems.signalservice.api.push.ContactTokenDetails;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;
import org.whispersystems.signalservice.api.push.SignedPreKeyEntity;
import org.whispersystems.signalservice.api.push.TrustStore;
import org.whispersystems.signalservice.api.push.exceptions.AuthorizationFailedException;
import org.whispersystems.signalservice.api.push.exceptions.ExpectationFailedException;
import org.whispersystems.signalservice.api.push.exceptions.NonSuccessfulResponseCodeException;
import org.whispersystems.signalservice.api.push.exceptions.NotFoundException;
import org.whispersystems.signalservice.api.push.exceptions.PushNetworkException;
import org.whispersystems.signalservice.api.push.exceptions.RateLimitException;
import org.whispersystems.signalservice.api.push.exceptions.UnregisteredUserException;
import org.whispersystems.signalservice.api.util.CredentialsProvider;
import org.whispersystems.signalservice.internal.push.exceptions.MismatchedDevicesException;
import org.whispersystems.signalservice.internal.push.exceptions.StaleDevicesException;
import org.whispersystems.signalservice.internal.util.Base64;
import org.whispersystems.signalservice.internal.util.BlacklistingTrustManager;
import org.whispersystems.signalservice.internal.util.JsonUtil;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import okhttp3.CertificatePinner;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okio.BufferedSink;

/**
 * @author Moxie Marlinspike
 */
public class PushServiceSocket {

  private static final String TAG = PushServiceSocket.class.getSimpleName();

  private static final String CREATE_ACCOUNT_SMS_PATH   = "/v1/accounts/sms/code/%s";
  private static final String CREATE_ACCOUNT_VOICE_PATH = "/v1/accounts/voice/code/%s";
  private static final String VERIFY_ACCOUNT_CODE_PATH  = "/v1/accounts/code/%s";
  private static final String VERIFY_ACCOUNT_TOKEN_PATH = "/v1/accounts/token/%s";
  private static final String REGISTER_GCM_PATH         = "/v1/accounts/gcm/";
  private static final String REQUEST_TOKEN_PATH        = "/v1/accounts/token";
  private static final String SET_ACCOUNT_ATTRIBUTES    = "/v1/accounts/attributes/";

  private static final String PREKEY_METADATA_PATH      = "/v2/keys/";
  private static final String PREKEY_PATH               = "/v2/keys/%s";
  private static final String PREKEY_DEVICE_PATH        = "/v2/keys/%s/%s";
  private static final String SIGNED_PREKEY_PATH        = "/v2/keys/signed";

  private static final String PROVISIONING_CODE_PATH    = "/v1/devices/provisioning/code";
  private static final String PROVISIONING_MESSAGE_PATH = "/v1/provisioning/%s";
  private static final String DEVICE_PATH               = "/v1/devices/%s";

  private static final String DIRECTORY_TOKENS_PATH     = "/v1/directory/tokens";
  private static final String DIRECTORY_VERIFY_PATH     = "/v1/directory/%s";
  private static final String MESSAGE_PATH              = "/v1/messages/%s";
  private static final String MESSAGE_PATH_DEVICE       = "/v1/messages/%s/%d";
  private static final String ACKNOWLEDGE_MESSAGE_PATH  = "/v1/messages/%s/%d";
  private static final String RECEIPT_PATH              = "/v1/receipt/%s/%d";
  private static final String ATTACHMENT_PATH           = "/v1/attachments/%s";

  private final String              serviceUrl;
  private final TrustManager[]      trustManagers;
  private final CredentialsProvider credentialsProvider;
  private final String              userAgent;

  public PushServiceSocket(String serviceUrl, TrustStore trustStore, CredentialsProvider credentialsProvider, String userAgent)
  {
    this.serviceUrl          = serviceUrl;
    this.credentialsProvider = credentialsProvider;
    if (trustStore != null) {
        this.trustManagers = BlacklistingTrustManager.createFor(trustStore);
    } else {
        this.trustManagers = null;
    }
    this.userAgent           = userAgent;
  }

  public void createAccount(boolean voice) throws IOException {
    String path = voice ? CREATE_ACCOUNT_VOICE_PATH : CREATE_ACCOUNT_SMS_PATH;
    makeRequest(String.format(path, credentialsProvider.getUser()), "GET", null);
  }

  public void verifyAccountCode(String verificationCode, String signalingKey, int registrationId, boolean voice)
      throws IOException
  {
    AccountAttributes signalingKeyEntity = new AccountAttributes(signalingKey, registrationId, voice);
    makeRequest(String.format(VERIFY_ACCOUNT_CODE_PATH, verificationCode),
                "PUT", JsonUtil.toJson(signalingKeyEntity));
  }

  public void verifyAccountToken(String verificationToken, String signalingKey, int registrationId, boolean voice)
      throws IOException
  {
    AccountAttributes signalingKeyEntity = new AccountAttributes(signalingKey, registrationId, voice);
    makeRequest(String.format(VERIFY_ACCOUNT_TOKEN_PATH, verificationToken),
                "PUT", JsonUtil.toJson(signalingKeyEntity));
  }

  public void setAccountAttributes(String signalingKey, int registrationId, boolean voice) throws IOException {
    AccountAttributes accountAttributes = new AccountAttributes(signalingKey, registrationId, voice);
    makeRequest(SET_ACCOUNT_ATTRIBUTES, "PUT", JsonUtil.toJson(accountAttributes));
  }

  public String getAccountVerificationToken() throws IOException {
    String responseText = makeRequest(REQUEST_TOKEN_PATH, "GET", null);
    return JsonUtil.fromJson(responseText, AuthorizationToken.class).getToken();
  }

  public String getNewDeviceVerificationCode() throws IOException {
    String responseText = makeRequest(PROVISIONING_CODE_PATH, "GET", null);
    return JsonUtil.fromJson(responseText, DeviceCode.class).getVerificationCode();
  }

  public List<DeviceInfo> getDevices() throws IOException {
    String responseText = makeRequest(String.format(DEVICE_PATH, ""), "GET", null);
    return JsonUtil.fromJson(responseText, DeviceInfoList.class).getDevices();
  }

  public void removeDevice(long deviceId) throws IOException {
    makeRequest(String.format(DEVICE_PATH, String.valueOf(deviceId)), "DELETE", null);
  }

  public void sendProvisioningMessage(String destination, byte[] body) throws IOException {
    makeRequest(String.format(PROVISIONING_MESSAGE_PATH, destination), "PUT",
                JsonUtil.toJson(new ProvisioningMessage(Base64.encodeBytes(body))));
  }

  public void sendReceipt(String destination, long messageId, Optional<String> relay) throws IOException {
    String path = String.format(RECEIPT_PATH, destination, messageId);

    if (relay.isPresent()) {
      path += "?relay=" + relay.get();
    }

    makeRequest(path, "PUT", null);
  }

  public void registerGcmId(String gcmRegistrationId) throws IOException {
    GcmRegistrationId registration = new GcmRegistrationId(gcmRegistrationId, true);
    makeRequest(REGISTER_GCM_PATH, "PUT", JsonUtil.toJson(registration));
  }

  public void unregisterGcmId() throws IOException {
    makeRequest(REGISTER_GCM_PATH, "DELETE", null);
  }

  public SendMessageResponse sendMessage(OutgoingPushMessageList bundle)
      throws IOException
  {
    try {
      String responseText = makeRequest(String.format(MESSAGE_PATH, bundle.getDestination()), "PUT", JsonUtil.toJson(bundle));

      if (responseText == null) return new SendMessageResponse(false);
      else                      return JsonUtil.fromJson(responseText, SendMessageResponse.class);
    } catch (NotFoundException nfe) {
      throw new UnregisteredUserException(bundle.getDestination(), nfe);
    }
  }

  public SendMessageResponse sendDeviceMessage(String address, int deviceId, OutgoingPushMessage bundle)
      throws IOException
  {
    try {
      String responseText = makeRequest(String.format(MESSAGE_PATH_DEVICE, address, deviceId), "PUT", JsonUtil.toJson(bundle));

      if (responseText == null) return new SendMessageResponse(false);
      else                      return JsonUtil.fromJson(responseText, SendMessageResponse.class);
    } catch (NotFoundException nfe) {
      throw new UnregisteredUserException(address, nfe);
    }
  }

  public List<SignalServiceEnvelopeEntity> getMessages() throws IOException {
    String responseText = makeRequest(String.format(MESSAGE_PATH, ""), "GET", null);
    return JsonUtil.fromJson(responseText, SignalServiceEnvelopeEntityList.class).getMessages();
  }

  public void acknowledgeMessage(String sender, long timestamp) throws IOException {
    makeRequest(String.format(ACKNOWLEDGE_MESSAGE_PATH, sender, timestamp), "DELETE", null);
  }

  public void registerPreKeys(IdentityKey identityKey,
                              PreKeyRecord lastResortKey,
                              SignedPreKeyRecord signedPreKey,
                              List<PreKeyRecord> records)
      throws IOException
  {
    List<PreKeyEntity> entities = new LinkedList<>();

    for (PreKeyRecord record : records) {
      PreKeyEntity entity = new PreKeyEntity(record.getId(),
                                             record.getKeyPair().getPublicKey());

      entities.add(entity);
    }

    PreKeyEntity lastResortEntity = new PreKeyEntity(lastResortKey.getId(),
                                                     lastResortKey.getKeyPair().getPublicKey());

    SignedPreKeyEntity signedPreKeyEntity = new SignedPreKeyEntity(signedPreKey.getId(),
                                                                   signedPreKey.getKeyPair().getPublicKey(),
                                                                   signedPreKey.getSignature());

    makeRequest(String.format(PREKEY_PATH, ""), "PUT",
                JsonUtil.toJson(new PreKeyState(entities, lastResortEntity,
                                                signedPreKeyEntity, identityKey)));
  }

  public int getAvailablePreKeys() throws IOException {
    String       responseText = makeRequest(PREKEY_METADATA_PATH, "GET", null);
    PreKeyStatus preKeyStatus = JsonUtil.fromJson(responseText, PreKeyStatus.class);

    return preKeyStatus.getCount();
  }

  public List<PreKeyBundle> getPreKeys(SignalServiceAddress destination, int deviceIdInteger) throws IOException {
    try {
      String deviceId = String.valueOf(deviceIdInteger);

      if (deviceId.equals("1"))
        deviceId = "*";

      String path = String.format(PREKEY_DEVICE_PATH, destination.getNumber(), deviceId);

      if (destination.getRelay().isPresent()) {
        path = path + "?relay=" + destination.getRelay().get();
      }

      String             responseText = makeRequest(path, "GET", null);
      PreKeyResponse     response     = JsonUtil.fromJson(responseText, PreKeyResponse.class);
      List<PreKeyBundle> bundles      = new LinkedList<>();

      for (PreKeyResponseItem device : response.getDevices()) {
        ECPublicKey preKey                = null;
        ECPublicKey signedPreKey          = null;
        byte[]      signedPreKeySignature = null;
        int         preKeyId              = -1;
        int         signedPreKeyId        = -1;

        if (device.getSignedPreKey() != null) {
          signedPreKey          = device.getSignedPreKey().getPublicKey();
          signedPreKeyId        = device.getSignedPreKey().getKeyId();
          signedPreKeySignature = device.getSignedPreKey().getSignature();
        }

        if (device.getPreKey() != null) {
          preKeyId = device.getPreKey().getKeyId();
          preKey   = device.getPreKey().getPublicKey();
        }

        bundles.add(new PreKeyBundle(device.getRegistrationId(), device.getDeviceId(), preKeyId,
                                     preKey, signedPreKeyId, signedPreKey, signedPreKeySignature,
                                     response.getIdentityKey()));
      }

      return bundles;
    } catch (NotFoundException nfe) {
      throw new UnregisteredUserException(destination.getNumber(), nfe);
    }
  }

  public PreKeyBundle getPreKey(SignalServiceAddress destination, int deviceId) throws IOException {
    try {
      String path = String.format(PREKEY_DEVICE_PATH, destination.getNumber(),
                                  String.valueOf(deviceId));

      if (destination.getRelay().isPresent()) {
        path = path + "?relay=" + destination.getRelay().get();
      }

      String         responseText = makeRequest(path, "GET", null);
      PreKeyResponse response     = JsonUtil.fromJson(responseText, PreKeyResponse.class);

      if (response.getDevices() == null || response.getDevices().size() < 1)
        throw new IOException("Empty prekey list");

      PreKeyResponseItem device                = response.getDevices().get(0);
      ECPublicKey        preKey                = null;
      ECPublicKey        signedPreKey          = null;
      byte[]             signedPreKeySignature = null;
      int                preKeyId              = -1;
      int                signedPreKeyId        = -1;

      if (device.getPreKey() != null) {
        preKeyId = device.getPreKey().getKeyId();
        preKey   = device.getPreKey().getPublicKey();
      }

      if (device.getSignedPreKey() != null) {
        signedPreKeyId        = device.getSignedPreKey().getKeyId();
        signedPreKey          = device.getSignedPreKey().getPublicKey();
        signedPreKeySignature = device.getSignedPreKey().getSignature();
      }

      return new PreKeyBundle(device.getRegistrationId(), device.getDeviceId(), preKeyId, preKey,
                              signedPreKeyId, signedPreKey, signedPreKeySignature, response.getIdentityKey());
    } catch (NotFoundException nfe) {
      throw new UnregisteredUserException(destination.getNumber(), nfe);
    }
  }

  public SignedPreKeyEntity getCurrentSignedPreKey() throws IOException {
    try {
      String responseText = makeRequest(SIGNED_PREKEY_PATH, "GET", null);
      return JsonUtil.fromJson(responseText, SignedPreKeyEntity.class);
    } catch (NotFoundException e) {
      Log.w(TAG, e);
      return null;
    }
  }

  public void setCurrentSignedPreKey(SignedPreKeyRecord signedPreKey) throws IOException {
    SignedPreKeyEntity signedPreKeyEntity = new SignedPreKeyEntity(signedPreKey.getId(),
                                                                   signedPreKey.getKeyPair().getPublicKey(),
                                                                   signedPreKey.getSignature());
    makeRequest(SIGNED_PREKEY_PATH, "PUT", JsonUtil.toJson(signedPreKeyEntity));
  }

  public String sendAttachment(PushAttachmentData attachment) throws IOException {
    return uploadAttachment("POST", serviceUrl + String.format(ATTACHMENT_PATH, ""),
            attachment.getData(), attachment.getDataSize(), attachment.getKey(), attachment.getListener());
  }

  public void retrieveAttachment(String relay, String attachmentId, File destination, ProgressListener listener) throws IOException {
    String path = serviceUrl + String.format(ATTACHMENT_PATH, String.valueOf(attachmentId));
    downloadExternalFile(path, destination, listener);
  }

  public List<ContactTokenDetails> retrieveDirectory(Set<String> contactTokens)
      throws NonSuccessfulResponseCodeException, PushNetworkException
  {
    try {
      ContactTokenList        contactTokenList = new ContactTokenList(new LinkedList<>(contactTokens));
      String                  response         = makeRequest(DIRECTORY_TOKENS_PATH, "PUT", JsonUtil.toJson(contactTokenList));
      ContactTokenDetailsList activeTokens     = JsonUtil.fromJson(response, ContactTokenDetailsList.class);

      return activeTokens.getContacts();
    } catch (IOException e) {
      Log.w(TAG, e);
      throw new NonSuccessfulResponseCodeException("Unable to parse entity");
    }
  }

  public ContactTokenDetails getContactTokenDetails(String contactToken) throws IOException {
    try {
      String response = makeRequest(String.format(DIRECTORY_VERIFY_PATH, contactToken), "GET", null);
      return JsonUtil.fromJson(response, ContactTokenDetails.class);
    } catch (NotFoundException nfe) {
      return null;
    }
  }

  private void downloadExternalFile(final String url, final File localDestination, final ProgressListener listener) throws IOException
  {
      URL downloadUrl = new URL(url);
      CertificatePinner certPinner = new CertificatePinner.Builder()
              .add("*.kalimdor.network",
                      "sha256/VtOB0C/9LihdefUvKEOHAB7f+IZgTvW+wfN9AzZ4tVg=")
              .build();
      OkHttpClient.Builder okHttpClientBuilder = new OkHttpClient.Builder();
      OkHttpClient okHttpClient;
      okHttpClientBuilder
              .certificatePinner(certPinner)
              .hostnameVerifier(new StrictHostnameVerifier());
      SSLContext context;
      try {
          context = SSLContext.getInstance("TLS");
          context.init(null, trustManagers, null);
          okHttpClientBuilder.sslSocketFactory(context.getSocketFactory());
      } catch (NoSuchAlgorithmException | KeyManagementException e) {
          e.printStackTrace();
      }
      okHttpClient = okHttpClientBuilder.build();

      Request request;
      Request.Builder requestBuilder = new Request.Builder()
              .url(downloadUrl)
              .addHeader("Content-Type", "application/octet-stream");
      if (credentialsProvider.getPassword() != null) {
          requestBuilder = requestBuilder
                  .addHeader("Authorization", getAuthorizationHeader());
      }
      if (userAgent != null) {
          requestBuilder = requestBuilder
                  .addHeader("X-Signal-Agent", userAgent);
      }
      request = requestBuilder.build();

      Response response = okHttpClient.newCall(request).execute();
      if (response.isSuccessful()) {
          try {
              OutputStream output        = new FileOutputStream(localDestination);
              InputStream  input         = response.body().byteStream();
              byte[]       buffer        = new byte[4096];
              long         contentLength = response.body().contentLength();
              int         read,totalRead = 0;

              while ((read = input.read(buffer)) != -1) {
                  output.write(buffer, 0, read);
                  totalRead += read;

                  if (listener != null) {
                      listener.onAttachmentProgress(contentLength, totalRead);
                  }
              }

              output.close();
              Log.w(TAG, "Downloaded: " + url + " to: " + localDestination.getAbsolutePath());
          } catch (IOException ioe) {
              throw new PushNetworkException(ioe);
          }
      } else {
          throw new NonSuccessfulResponseCodeException("Bad response: " + response.code());
      }
  }

  private String uploadAttachment(String method, String url, final InputStream data,
                                  final long dataSize, final byte[] key, final ProgressListener listener)
          throws IOException
  {
      URL uploadUrl  = new URL(url);
      CertificatePinner certPinner = new CertificatePinner.Builder()
              .add("*.kalimdor.network",
                      "sha256/VtOB0C/9LihdefUvKEOHAB7f+IZgTvW+wfN9AzZ4tVg=")
              .build();
      OkHttpClient.Builder okHttpClientBuilder = new OkHttpClient.Builder();
      OkHttpClient okHttpClient;
      okHttpClientBuilder
              .certificatePinner(certPinner)
              .hostnameVerifier(new StrictHostnameVerifier());
      SSLContext context;
      try {
          context = SSLContext.getInstance("TLS");
          context.init(null, trustManagers, null);
          okHttpClientBuilder.sslSocketFactory(context.getSocketFactory());
      } catch (NoSuchAlgorithmException | KeyManagementException e) {
          e.printStackTrace();
      }
      okHttpClient = okHttpClientBuilder.build();

      RequestBody requestBody = new RequestBody() {
          @Override
          public MediaType contentType() {
              return MediaType.parse("application/octet-stream");
          }

          @Override
          public void writeTo(BufferedSink sink) throws IOException {
              AttachmentCipherOutputStream out    = new AttachmentCipherOutputStream(key, sink.outputStream());
              byte[]                       buffer = new byte[4096];
              int                   read, written = 0;

              while ((read = data.read(buffer)) != -1) {
                  out.write(buffer, 0, read);
                  written += read;

                  if (listener != null) {
                      listener.onAttachmentProgress(dataSize, written);
                  }
              }

              data.close();
              out.flush();
              out.close();
          }
      };

      Request request;
      Request.Builder requestBuilder = new Request.Builder()
              .url(uploadUrl)
              .method(method, requestBody)
              .addHeader("Connection", "close")
              .addHeader("Content-Type", "application/octet-stream");
      if (credentialsProvider.getPassword() != null) {
          requestBuilder = requestBuilder
                  .addHeader("Authorization", getAuthorizationHeader());
      }
      if (userAgent != null) {
          requestBuilder = requestBuilder
                  .addHeader("X-Signal-Agent", userAgent);
      }
      request = requestBuilder.build();

      Response response = okHttpClient.newCall(request).execute();
      if (response.isSuccessful()) {
          try {
              InputStream responseStream = new BufferedInputStream(response.body().byteStream());
              BufferedReader responseStreamReader = new BufferedReader(new InputStreamReader(responseStream));
              String line = "";
              StringBuilder stringBuilder = new StringBuilder();
              while ((line = responseStreamReader.readLine()) != null) {
                  stringBuilder.append(line);
              }
              responseStreamReader.close();
              return stringBuilder.toString();
          } catch (IOException ioe) {
              throw new PushNetworkException(ioe);
          }
      } else {
          throw new IOException("Bad response: " + response.code() + " " + response.message());
      }
  }

//  private String uploadAttachment(String method, String url, InputStream data,
//                                long dataSize, byte[] key, ProgressListener listener)
//  {
//    try {
//      String crlf = "\r\n";
//      String twoHyphens = "--";
//      String boundary = "*****";
//
//      URL uploadUrl = new URL(url);
//      HttpsURLConnection connection = (HttpsURLConnection) uploadUrl.openConnection();
//      connection.setDoOutput(true);
//      connection.setUseCaches(false);
//      connection.setRequestMethod("POST");
//      connection.setRequestProperty("Connection", "close");
//      connection.setRequestProperty("Cache-Control", "no-cache");
//      connection.setRequestProperty("Content-Type", "multipart/form-data;boundary=" + boundary);
//
//      setRequestAuthorisation(connection);
//
//      byte[] attachmentContentDisposition = ("Content-Disposition: form-data; name=\"attachment\"" + crlf).getBytes();
//      byte[] octetStreamContentType = ("Content-Type: application/octet-stream" + crlf).getBytes();
//      byte[] boundaryLine = (twoHyphens + boundary + crlf).getBytes();
//      byte[] boundaryLastLine = (twoHyphens + boundary + twoHyphens).getBytes();
//      byte[] crlfBytes = crlf.getBytes();
//      long streamingLength = (int) AttachmentCipherOutputStream.getCiphertextLength(dataSize)
//              + boundaryLine.length + boundaryLastLine.length + 2 * crlfBytes.length
//              + attachmentContentDisposition.length + octetStreamContentType.length;
////      if (dataSize > 0) {
////        connection.setFixedLengthStreamingMode(streamingLength);
////      } else {
//        connection.setChunkedStreamingMode(0);
////      }
//
//      DataOutputStream header = new DataOutputStream(connection.getOutputStream());
//      AttachmentCipherOutputStream body = new AttachmentCipherOutputStream(key, connection.getOutputStream());
//      header.write(boundaryLine);
//      header.write(attachmentContentDisposition);
//      header.write(octetStreamContentType);
//      header.write(crlfBytes);
//      int nRead, written = 0;
//      byte[] buffer = new byte[4096];
//      while ((nRead = data.read(buffer)) != -1) {
//        body.write(buffer, 0, nRead);
//        written += nRead;
//        if (listener != null) {
//          listener.onAttachmentProgress(dataSize, written);
//        }
//      }
//      header.write(crlfBytes);
//      header.write(boundaryLastLine);
//      header.close();
//      body.close();
//
//      InputStream responseStream = new BufferedInputStream(connection.getInputStream());
//      BufferedReader responseStreamReader = new BufferedReader(new InputStreamReader(responseStream));
//      String line = "";
//      StringBuilder stringBuilder = new StringBuilder();
//      while ((line = responseStreamReader.readLine()) != null) {
//        stringBuilder.append(line);
//      }
//      responseStreamReader.close();
//      String response = stringBuilder.toString();
//      connection.disconnect();
//      return response;
//    } catch (Exception e) {
//      return e.toString();
//    }
//  }

  private String makeRequest(String urlFragment, String method, String body)
      throws NonSuccessfulResponseCodeException, PushNetworkException
  {
    Response response = getConnection(urlFragment, method, body);

    int    responseCode;
    String responseMessage;
    String responseBody;

    try {
      responseCode    = response.code();
      responseMessage = response.message();
      responseBody    = response.body().string();
    } catch (IOException ioe) {
      throw new PushNetworkException(ioe);
    }

    switch (responseCode) {
      case 413:
        throw new RateLimitException("Rate limit exceeded: " + responseCode);
      case 401:
      case 403:
        throw new AuthorizationFailedException("Authorization failed!");
      case 404:
        throw new NotFoundException("Not found");
      case 409:
        MismatchedDevices mismatchedDevices;

        try {
          mismatchedDevices = JsonUtil.fromJson(responseBody, MismatchedDevices.class);
        } catch (JsonProcessingException e) {
          Log.w(TAG, e);
          throw new NonSuccessfulResponseCodeException("Bad response: " + responseCode + " " + responseMessage);
        } catch (IOException e) {
          throw new PushNetworkException(e);
        }

        throw new MismatchedDevicesException(mismatchedDevices);
      case 410:
        StaleDevices staleDevices;

        try {
          staleDevices = JsonUtil.fromJson(responseBody, StaleDevices.class);
        } catch (JsonProcessingException e) {
          throw new NonSuccessfulResponseCodeException("Bad response: " + responseCode + " " + responseMessage);
        } catch (IOException e) {
          throw new PushNetworkException(e);
        }

        throw new StaleDevicesException(staleDevices);
      case 411:
        DeviceLimit deviceLimit;

        try {
          deviceLimit = JsonUtil.fromJson(responseBody, DeviceLimit.class);
        } catch (JsonProcessingException e) {
          throw new NonSuccessfulResponseCodeException("Bad response: " + responseCode + " " + responseMessage);
        } catch (IOException e) {
          throw new PushNetworkException(e);
        }

        throw new DeviceLimitExceededException(deviceLimit);
      case 417:
        throw new ExpectationFailedException();
    }

    if (responseCode != 200 && responseCode != 204) {
        throw new NonSuccessfulResponseCodeException("Bad response: " + responseCode + " " +
                                                     responseMessage);
    }

    return responseBody;
  }

  private Response getConnection(String urlFragment, String method, String body)
      throws PushNetworkException
  {
    try {
      Log.w(TAG, "Push service URL: " + serviceUrl);
      Log.w(TAG, "Opening URL: " + String.format("%s%s", serviceUrl, urlFragment));

      SSLContext context = SSLContext.getInstance("TLS");
      context.init(null, trustManagers, null);

        CertificatePinner certPinner = new CertificatePinner.Builder()
                .add("*.kalimdor.network",
                        "sha256/VtOB0C/9LihdefUvKEOHAB7f+IZgTvW+wfN9AzZ4tVg=")
                .build();

      OkHttpClient okHttpClient = new OkHttpClient.Builder()
              .certificatePinner(certPinner)
              .hostnameVerifier(new StrictHostnameVerifier())
              .sslSocketFactory(context.getSocketFactory())
              .build();

      Request.Builder request = new Request.Builder();
      request.url(String.format("%s%s", serviceUrl, urlFragment));

      if (body != null) {
        request.method(method, RequestBody.create(MediaType.parse("application/json"), body));
      } else {
        request.method(method, null);
      }

      if (credentialsProvider.getPassword() != null) {
        request.addHeader("Authorization", getAuthorizationHeader());
      }

      if (userAgent != null) {
        request.addHeader("X-Signal-Agent", userAgent);
      }

      return okHttpClient.newCall(request.build()).execute();
    } catch (IOException e) {
      throw new PushNetworkException(e);
    } catch (NoSuchAlgorithmException | KeyManagementException e) {
      throw new AssertionError(e);
    }
  }

  private String getAuthorizationHeader() {
    try {
      return "Basic " + Base64.encodeBytes((credentialsProvider.getUser() + ":" + credentialsProvider.getPassword()).getBytes("UTF-8"));
    } catch (UnsupportedEncodingException e) {
      throw new AssertionError(e);
    }
  }

  private static class GcmRegistrationId {

    @JsonProperty
    private String gcmRegistrationId;

    @JsonProperty
    private boolean webSocketChannel;

    public GcmRegistrationId() {}

    public GcmRegistrationId(String gcmRegistrationId, boolean webSocketChannel) {
      this.gcmRegistrationId = gcmRegistrationId;
      this.webSocketChannel  = webSocketChannel;
    }
  }

  private static class AttachmentDescriptor {
    @JsonProperty
    private long id;

    @JsonProperty
    private String location;

    public long getId() {
      return id;
    }

    public String getLocation() {
      return location;
    }
  }
}
