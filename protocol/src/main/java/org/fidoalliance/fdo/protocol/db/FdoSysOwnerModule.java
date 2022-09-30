// Copyright 2022 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package org.fidoalliance.fdo.protocol.db;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Blob;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.fidoalliance.fdo.protocol.Config;
import org.fidoalliance.fdo.protocol.HttpClientSupplier;
import org.fidoalliance.fdo.protocol.InternalServerErrorException;
import org.fidoalliance.fdo.protocol.LoggerService;
import org.fidoalliance.fdo.protocol.Mapper;
import org.fidoalliance.fdo.protocol.SvcCallProtocol;
import org.fidoalliance.fdo.protocol.dispatch.ServiceInfoModule;
import org.fidoalliance.fdo.protocol.dispatch.ServiceInfoSendFunction;
import org.fidoalliance.fdo.protocol.dispatch.VoucherQueryFunction;
import org.fidoalliance.fdo.protocol.entity.SystemPackage;
import org.fidoalliance.fdo.protocol.entity.SystemResource;
import org.fidoalliance.fdo.protocol.message.AnyType;
import org.fidoalliance.fdo.protocol.message.CoseSign1;
import org.fidoalliance.fdo.protocol.message.DevModList;
import org.fidoalliance.fdo.protocol.message.EotResult;
import org.fidoalliance.fdo.protocol.message.FetchMessage;
import org.fidoalliance.fdo.protocol.message.OwnershipVoucher;
import org.fidoalliance.fdo.protocol.message.OwnershipVoucherEntries;
import org.fidoalliance.fdo.protocol.message.OwnershipVoucherEntryPayload;
import org.fidoalliance.fdo.protocol.message.ServiceInfoKeyValuePair;
import org.fidoalliance.fdo.protocol.message.ServiceInfoModuleState;
import org.fidoalliance.fdo.protocol.message.ServiceInfoQueue;
import org.fidoalliance.fdo.protocol.message.StatusCb;
import org.fidoalliance.fdo.protocol.message.StatusCbExtended;
import org.fidoalliance.fdo.protocol.serviceinfo.DevMod;
import org.fidoalliance.fdo.protocol.serviceinfo.FdoSys;
import org.hibernate.Session;
import org.hibernate.Transaction;

/**
 * Implements FdoSysModule spec.
 */
public class FdoSysOwnerModule implements ServiceInfoModule {

  static final String SVC_URL_CACHE_KEY = "svcUrlCacheKey";

  public FdoSysOwnerModule() {
    varMap = new HashMap<>();
    svcUrlMap = new HashMap<>();
  }

  private Map<String, Object> varMap;
  private Map<String, String[]> svcUrlMap;

  private LoggerService logger = new LoggerService(FdoSysOwnerModule.class);

  @Override
  public String getName() {
    return FdoSys.NAME;
  }

  @Override
  public void prepare(ServiceInfoModuleState state) throws IOException {
    state.setExtra(AnyType.fromObject(new FdoSysModuleExtra()));
  }

  @Override
  public void receive(ServiceInfoModuleState state, ServiceInfoKeyValuePair kvPair)
      throws IOException {
    FdoSysModuleExtra extra = state.getExtra().covertValue(FdoSysModuleExtra.class);
    switch (kvPair.getKey()) {
      case DevMod.KEY_MODULES: {
        logger.error("DEBUG=============== In Key mod");
        DevModList list =
            Mapper.INSTANCE.readValue(kvPair.getValue(), DevModList.class);
        for (String name : list.getModulesNames()) {
          if (name.equals(FdoSys.NAME)) {
            state.setActive(true);
            ServiceInfoQueue queue = extra.getQueue();
            ServiceInfoKeyValuePair activePair = new ServiceInfoKeyValuePair();
            activePair.setKeyName(FdoSys.ACTIVE);
            activePair.setValue(Mapper.INSTANCE.writeValue(true));
            queue.add(activePair);

          }
        }
      }
      break;
      case DevMod.KEY_DEVICE:
      case DevMod.KEY_OS:
      case DevMod.KEY_VERSION:
      case DevMod.KEY_ARCH:
        logger.error("DEBUG=============== In Dev");
        extra.getFilter().put(kvPair.getKey(),
            Mapper.INSTANCE.readValue(kvPair.getValue(), String.class));
        break;
      case FdoSys.STATUS_CB:
        logger.error("DEBUG=============== In Cb");
        if (state.isActive()) {
          StatusCbExtended statusCbExt = Mapper.INSTANCE.readValue(
                  kvPair.getValue(), StatusCbExtended.class);

          StatusCb status = new StatusCb();
          status.setCompleted(statusCbExt.isCompleted());
          status.setTimeout(statusCbExt.getTimeout());
          status.setRetCode(statusCbExt.getRetCode());

          //send notification of status
          ServiceInfoKeyValuePair kv = new ServiceInfoKeyValuePair();
          kv.setKeyName(FdoSys.STATUS_CB);
          kv.setValue(Mapper.INSTANCE.writeValue(status));
          extra.getQueue().add(kv);

          String mapKey = statusCbExt.getSviMapKey();
          onStatusCb(state, extra, statusCbExt, mapKey);
          if (statusCbExt.isCompleted()) {
            // check for error
            if (statusCbExt.getRetCode() != 0) {
              throw new InternalServerErrorException("Exec_cb status returned failure.");
            }
            extra.setWaiting(false);
            extra.getQueue().addAll(extra.getWaitQueue());
            extra.setWaitQueue(new ServiceInfoQueue());
          }
        }
        break;
      case FdoSys.DATA: {
        logger.error("DEBUG=============== In Data");
        if (state.isActive()) {
          FetchMessage msg = Mapper.INSTANCE.readValue(kvPair.getValue(), FetchMessage.class);
          byte[] data = msg.getDataBytes();
          String sviMapKey = msg.getSviMapKey();
          onFetch(state, extra, data, sviMapKey);
        }
      }
      break;
      case FdoSys.EOT:
        logger.error("DEBUG=============== In EOT ");
        if (state.isActive()) {
          extra.setWaiting(false);
          extra.setQueue(extra.getWaitQueue());
          extra.setWaitQueue(new ServiceInfoQueue());
          EotResult result = Mapper.INSTANCE.readValue(kvPair.getValue(), EotResult.class);
          onEot(state, extra, result);
        }
        break;
      case FdoSys.SVC_URL:
        logger.error("DEBUG=============== In SVC ");
        if (state.isActive()) {
          extra.setWaiting(false);
          extra.setQueue(extra.getWaitQueue());
          extra.setWaitQueue(new ServiceInfoQueue());

          String svcUrlKey = Mapper.INSTANCE.readValue(kvPair.getValue(), String.class);
          svcUrlKey = svcUrlKey.trim();
          logger.error("DEBUG=============== Response " + svcUrlKey);
          logger.error("DEBUG=============== Key " + svcUrlKey + " Size " + svcUrlKey.length());
          String[] svcUrlArgs = svcUrlMap.get(svcUrlKey);
          logger.error("DEBUG=============== Map size " + svcUrlMap.size());
          logger.error("DEBUG=============== From map " + svcUrlArgs);
          makeSvcCall(state, extra, svcUrlArgs);
        }
        break;
      default:
        logger.error("DEBUG=============== In Default ");
        break;
    }
    state.setExtra(AnyType.fromObject(extra));
  }

  @Override
  public void send(ServiceInfoModuleState state, ServiceInfoSendFunction sendFunction)
      throws IOException {

    FdoSysModuleExtra extra = state.getExtra().covertValue(FdoSysModuleExtra.class);
    if (!extra.isLoaded() && infoReady(extra)) {
      load(state, extra);
      extra.setLoaded(true);
    }

    while (extra.getQueue().size() > 0) {
      boolean sent = sendFunction.apply(extra.getQueue().peek());
      if (sent) {
        logger.error("DEBUG=============== IN send ");
        checkWaiting(extra, extra.getQueue().poll());
      } else {
        break;
      }
      if (extra.isWaiting()) {
        break;
      }
    }
    if (extra.getQueue().size() == 0 && !extra.isWaiting()) {
      state.setDone(true);
    }
    state.setExtra(AnyType.fromObject(extra));
  }

  protected void checkWaiting(FdoSysModuleExtra extra, ServiceInfoKeyValuePair kv) {
    switch (kv.getKey()) {
      case FdoSys.EXEC_CB:
      case FdoSys.FETCH:
      case FdoSys.SVC_URL:
        extra.setWaiting(true);
        extra.setWaitQueue(extra.getQueue());
        extra.setQueue(new ServiceInfoQueue());
        break;
      default:
        break;
    }
  }

  protected boolean infoReady(FdoSysModuleExtra extra) {
    return extra.getFilter().containsKey(DevMod.KEY_DEVICE)
        && extra.getFilter().containsKey(DevMod.KEY_OS)
        && extra.getFilter().containsKey(DevMod.KEY_VERSION)
        && extra.getFilter().containsKey(DevMod.KEY_ARCH);
  }

  protected boolean checkFilter(Map<String, String> devMap, Map<String, String> filterMap) {
    return devMap.entrySet().containsAll(filterMap.entrySet());
  }

  private Map<String, byte[]> sviMap = new HashMap<>();

  protected void onStatusCb(ServiceInfoModuleState state, FdoSysModuleExtra extra,
      StatusCbExtended status, String mapKey) throws IOException {
    logger.info("status_cb completed " + status.isCompleted() + " retcode "
        + status.getRetCode() + " timeout " + status.getTimeout());
    logger.info("output of cmd execution on owner: " + status.getExecResult());
    if (mapKey.isEmpty()) {
      return;
    }

    if (!varMap.containsKey(mapKey)) {
      varMap.put(mapKey, status.getExecResult());
    }
  }

  protected void onFetch(ServiceInfoModuleState state, FdoSysModuleExtra extra,
      byte[] data, String sviMapKey) throws IOException {
    logger.info("data fetched::: ");
    logger.warn(new String(data, StandardCharsets.US_ASCII));
    if (varMap.containsKey(sviMapKey)) {
      logger.warn(varMap.get(sviMapKey));
    }
    // store the result of fetch in map
    varMap.put(sviMapKey, new String(data, StandardCharsets.UTF_8));

    // Persist the data fetched from device to file
    try {
      Set<StandardOpenOption> options = new HashSet<>();
      options.add(StandardOpenOption.CREATE);
      options.add(StandardOpenOption.WRITE);
      try (FileChannel channel = FileChannel.open(Paths.get("fetch_data.txt"), options)) {
        logger.info("writing to file channel..");
        channel.write(ByteBuffer.wrap(data));
      }
    } catch (IOException ex) {
      logger.error("IOException while saving fetch data..");
      throw new InternalServerErrorException(ex);
    }
  }

  protected void onEot(ServiceInfoModuleState state, FdoSysModuleExtra extra, EotResult result)
      throws IOException {
    logger.info("EOT:resultCode " + result.getResult());
  }

  protected void load(ServiceInfoModuleState state, FdoSysModuleExtra extra)
      throws IOException {

    if (!state.isActive()) {
      return;
    }
    final Session session = HibernateUtil.getSessionFactory().openSession();
    try {
      Transaction trans = session.beginTransaction();
      SystemPackage systemPackage =
          session.find(SystemPackage.class, Long.valueOf(1));

      if (systemPackage != null) {
        String body = systemPackage.getData().getSubString(1,
            Long.valueOf(systemPackage.getData().length()).intValue());
        FdoSysInstruction[] instructions =
            Mapper.INSTANCE.readJsonValue(body, FdoSysInstruction[].class);

        boolean skip = false;
        for (FdoSysInstruction instruction : instructions) {
          if (instruction.getFilter() != null) {
            skip = checkFilter(extra.getFilter(), instruction.getFilter());
          }
          if (skip) {
            continue;
          }

          if (instruction.getFileDesc() != null) {
            getFile(state, extra, instruction);
          } else if (instruction.getExecArgs() != null) {
            getExec(state, extra, instruction);
          } else if (instruction.getExecCbArgs() != null) {
            getExecCb(state, extra, instruction);
          } else if (instruction.getFetchArgs() != null) {
            getFetch(state, extra, instruction);
          } else if (instruction.getSvcUrlArgs() != null) {
            sendSvcCall(state, extra, instruction);
          }
        }
      }
      trans.commit();
    } catch (SQLException | CertificateException e) {
      throw new InternalServerErrorException(e);
    } finally {
      session.close();
    }
  }

  protected void sendSvcCall(ServiceInfoModuleState state,
                            FdoSysModuleExtra extra,
                            FdoSysInstruction instruction)
                      throws IOException, CertificateException {

    if (varMap.get("tpmEc") == null) {
      String deviceGuid = state.getGuid().toString();
      OwnershipVoucher voucher = Config.getWorker(VoucherQueryFunction.class).apply(deviceGuid);
      OwnershipVoucherEntries entries = voucher.getEntries();
      CoseSign1 entry = entries.getLast();

      OwnershipVoucherEntryPayload entryPayload =
              Mapper.INSTANCE.readValue(entry.getPayload(), OwnershipVoucherEntryPayload.class);
      byte[] bytes = entryPayload.getExtra();
      String hello = new String(bytes, StandardCharsets.UTF_8);
      X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
              .generateCertificate(new ByteArrayInputStream(bytes));

      // String b64EncodedTpmEc = Base64.getEncoder().encodeToString(cert.getEncoded());
      final StringWriter writer = new StringWriter();
      final JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
      pemWriter.writeObject(cert);
      pemWriter.flush();
      pemWriter.close();
      String tpmEc = writer.toString();

      logger.error("DEBUG=============== tpmEc " + tpmEc);
      String b64TpmEc = Base64.getEncoder().encodeToString(tpmEc.getBytes());
      varMap.put("tpmEc", b64TpmEc);
      logger.error("DEBUG=============== b64encoded " + b64TpmEc);
    }

    ServiceInfoKeyValuePair kv = new ServiceInfoKeyValuePair();
    kv.setKeyName(FdoSys.SVC_URL);
    Integer size = svcUrlMap.size();
    String key =  SVC_URL_CACHE_KEY + size;
    logger.error("DEBUG====================== Key " + key + " Size " + key.length());
    logger.error("DEBUG====================== svcUrlArgs" + instruction.getSvcUrlArgs());
    svcUrlMap.put(key, instruction.getSvcUrlArgs());
    kv.setValue(Mapper.INSTANCE.writeValue(key));
    extra.getQueue().add(kv);
    return;
  }

  private void makeSvcCall(ServiceInfoModuleState state,
                           FdoSysModuleExtra extra,
                           String[] svcUrlArgs) throws IOException {
    // Obtain the protocol from arg 0
    String protocolStr = svcUrlArgs[0];
    int protocol = Integer.parseInt(protocolStr);
    SvcCallProtocol x = null;
    for (SvcCallProtocol p : SvcCallProtocol.values()) {
      if (p.toInteger() == protocol) {
        x = p;
      }
    }

    switch (x) {
      case HTTPS:
        makeHttpRestCall(state, extra, svcUrlArgs);
        break;
      case FTP:
        break;
      case WS:
        break;
      default:
        break;
    }
  }

  protected void makeHttpRestCall(ServiceInfoModuleState state,
                                  FdoSysModuleExtra extra,
                                  String[] svcUrlArgs) throws IOException {
    try (CloseableHttpClient httpClient = Config.getWorker(ServiceInfoHttpClientSupplier.class)
            .get()) {

      String url = svcUrlArgs[1];
      String urlParamsStr = svcUrlArgs[4];
      String responseStr = svcUrlArgs[6]; // comma separated values
      String[] responses = {};
      if (responseStr != null && !responseStr.isEmpty()) {
        responses = responseStr.split(",");
      }
      URIBuilder builder = getBaseBuilder(url);
      logger.error("DEBUG=============== urlParam");
      if (urlParamsStr != null && !urlParamsStr.isEmpty()) {
        logger.error("DEBUG=============== urlParam : " + urlParamsStr);
        Map<String, Object> map = new ObjectMapper().readValue(urlParamsStr,
                               new TypeReference<>(){});
        for (Map.Entry<String, Object> e : map.entrySet()) {
          String inVal = (String)e.getValue();
          String paramVal = (String)varMap.get(inVal);
          builder.setParameter(e.getKey(), paramVal == null ? inVal : paramVal);
        }
      }
      String bodyStr = svcUrlArgs[5];
      HttpUriRequest httpRequest = null;
      String httpMethodStr = svcUrlArgs[2];
      int httpMethod = Integer.parseInt(httpMethodStr);
      switch (httpMethod) {
        case FdoSys.SVC_CALL_HTTP_METHOD_GET:
          httpRequest = new HttpGet(builder.build());
          logger.info("HTTP GET method requested for REST endpoint : " + httpRequest.toString());
          break;
        case FdoSys.SVC_CALL_HTTP_METHOD_POST:
          logger.error("DEBUG=============== bodyStr");
          logger.error("DEBUG=============== bodySt : " +  bodyStr);
          StringBuilder sb = new StringBuilder("{");
          if (bodyStr != null) {
            Map<String, Object> map = new ObjectMapper().readValue(bodyStr,
                    new TypeReference<>(){});
            int size = map.size();
            int counter = 0;
            for (Map.Entry<String, Object> e : map.entrySet()) {
              String inVal = (String)e.getValue();
              String bodyVal = (String)varMap.get(inVal);
              sb.append("\"" + e.getKey() + "\" : ");
              String val = bodyVal == null ? inVal : bodyVal;
              if (val.startsWith("[") || val.startsWith("{")) {
                sb.append(val);
              } else {
                sb.append("\"" + val + "\"");
              }
              counter += 1;
              sb.append(counter < size ? ", " : "}");
            }
          }

          HttpPost httpPost = new HttpPost(builder.build());
          logger.error("DEBUG=============== bodyStr : " +  sb.toString());
          httpPost.setEntity(new StringEntity(sb.toString(), ContentType.APPLICATION_JSON));

          httpRequest = httpPost;
          logger.info("HTTP POST method requested for REST endpoint : " + url);
          break;
        case FdoSys.SVC_CALL_HTTP_METHOD_PUT:
          httpRequest = new HttpPut(builder.build());
          logger.info("HTTP PUT method requested for REST endpoint : " + url);
          break;
        case FdoSys.SVC_CALL_HTTP_METHOD_DELETE:
          httpRequest = new HttpDelete(builder.build());
          logger.info("HTTP DELETE method requested for REST endpoint : " + url);
          break;
        default:
          logger.error("HTTP method not supported");
      }

      String headersStr = svcUrlArgs[3];
      logger.error("DEBUG=============== header");
      if (headersStr != null && !headersStr.isEmpty()) {
        logger.error("DEBUG=============== header : " + headersStr);
        Map<String, Object> map = new ObjectMapper().readValue(headersStr, 
                        new TypeReference<>(){});
        for (Map.Entry<String, Object> e : map.entrySet()) {
          String inVal = (String)e.getValue();
          String headerVal = (String)varMap.get(inVal);
          logger.error("DEBUG=============== header : " + e.getKey() + " Value : " + headerVal);
          httpRequest.addHeader(e.getKey(), headerVal == null ? inVal : headerVal);
        }
      }

      try (CloseableHttpResponse httpResponse = httpClient.execute(httpRequest);) {
        logger.info(httpResponse.getStatusLine().toString());

        int responseCode = svcUrlArgs.length == 8 ? Integer.parseInt(svcUrlArgs[7]) : 200;
        if (httpResponse.getStatusLine().getStatusCode() != responseCode) {
          throw new InternalServerErrorException(httpResponse.getStatusLine().toString());
        }
        HttpEntity entity = httpResponse.getEntity();
        if (entity != null) {
          logger.info("content length is " + entity.getContentLength());
          String responseString = EntityUtils.toString(entity, "UTF-8");
          logger.error("BYTE DEBUG============ " + responseString.length() + " " + responseString);

          // Content-type : application/jwt
          if (ContentType.getOrDefault(entity).getMimeType().equals("application/jwt")) {
            logger.error("DEBUG================ jwt");
            varMap.put(responses[0], "Bearer " + responseString);
          } else {
            // Not taking care of nested object for now. Expects a plain JSON Object.
            // Else handling on application/json
            logger.error("DEBUG================ nonjwt");
            Map<String, Object> map = new ObjectMapper().readValue(responseString,
                    new TypeReference<>() {}
                );

            for (String k : responses) {
              String val = (String) map.get(k);
              if (val != null) {
                varMap.put(k, val);
              }
            }
          }
        }
      }
    } catch (Exception e) {
      logger.error("Failed to make http(s) REST call : " + e);
      throw new InternalServerErrorException(e);
    }
    logger.info("HTTP(S) REST call completed successfully!");
  }

  private URIBuilder getBaseBuilder(String url) {
    URIBuilder builder = new URIBuilder();
    builder.setScheme(url.split(":")[0]);
    String urlPart = url.split("//")[1];
    String urlSock = urlPart.split("/")[0];
    builder.setHost(urlSock.split(":")[0]);
    if (urlSock.contains(":")) {
      builder.setPort(Integer.parseInt(urlSock.split(":")[1]));
    }
    builder.setPath(urlPart.substring(urlPart.indexOf("/"), urlPart.length()));

    return builder;
  }

  protected void getExec(ServiceInfoModuleState state,
      FdoSysModuleExtra extra,
      FdoSysInstruction instruction) throws IOException {
    ServiceInfoKeyValuePair kv = new ServiceInfoKeyValuePair();
    kv.setKeyName(FdoSys.EXEC);
    kv.setValue(Mapper.INSTANCE.writeValue(instruction.getExecArgs()));
    extra.getQueue().add(kv);
  }

  protected void getExecCb(ServiceInfoModuleState state,
      FdoSysModuleExtra extra,
      FdoSysInstruction instruction) throws IOException {

    ServiceInfoKeyValuePair kv = new ServiceInfoKeyValuePair();
    kv.setKeyName(FdoSys.EXEC_CB);
    kv.setValue(Mapper.INSTANCE.writeValue(instruction.getExecCbArgs()));
    extra.getQueue().add(kv);
  }

  protected void getFetch(ServiceInfoModuleState state,
      FdoSysModuleExtra extra,
      FdoSysInstruction instruction) throws IOException {
    ServiceInfoKeyValuePair kv = new ServiceInfoKeyValuePair();
    kv.setKeyName(FdoSys.FETCH);
    kv.setValue(Mapper.INSTANCE.writeValue(instruction.getFetchArgs()));
    extra.getQueue().add(kv);
  }

  protected void getDbFile(ServiceInfoModuleState state,
      FdoSysModuleExtra extra,
      FdoSysInstruction instruction) throws IOException {
    String resource = instruction.getResource();
    final Session session = HibernateUtil.getSessionFactory().openSession();
    try {
      Transaction trans = session.beginTransaction();
      resource = resource.replace("$(guid)", state.getGuid().toString());

      // Query database table SYSTEM_RESOURCE for filename Key
      SystemResource sviResource = session.get(SystemResource.class, resource);

      if (sviResource != null) {
        Blob blobData = sviResource.getData();
        try (InputStream input = blobData.getBinaryStream()) {
          for (; ; ) {
            byte[] data = new byte[state.getMtu() - 26];
            int br = input.read(data);
            if (br == -1) {
              break;
            }
            ServiceInfoKeyValuePair kv = new ServiceInfoKeyValuePair();
            kv.setKeyName(FdoSys.WRITE);

            if (br < data.length) {
              byte[] temp = data;
              data = new byte[br];
              System.arraycopy(temp, 0, data, 0, br);
            }
            kv.setValue(Mapper.INSTANCE.writeValue(data));
            extra.getQueue().add(kv);
          }
        } catch (SQLException throwables) {
          throw new InternalServerErrorException(throwables);
        }
      } else {
        throw new InternalServerErrorException("svi resource missing " + resource);
      }
      trans.commit();

    } finally {
      session.close();
    }

  }

  protected void getUrlFile(ServiceInfoModuleState state,
      FdoSysModuleExtra extra,
      FdoSysInstruction instruction) throws IOException {
    String resource = instruction.getResource();
    resource = resource.replace("$(guid)", state.getGuid().toString());

    try (CloseableHttpClient httpClient = Config.getWorker(HttpClientSupplier.class)
        .get()) {

      logger.info("HTTP(S) GET: " + resource);
      HttpGet httpRequest = new HttpGet(resource);
      try (CloseableHttpResponse httpResponse = httpClient.execute(httpRequest);) {
        logger.info(httpResponse.getStatusLine().toString());
        /*if (httpResponse.getStatusLine().getStatusCode() != 200) {
          throw new InternalServerErrorException(httpResponse.getStatusLine().toString());
        }
        */
        HttpEntity entity = httpResponse.getEntity();
        if (entity != null) {
          logger.info("content length is " + entity.getContentLength());

          try (InputStream input = entity.getContent()) {
            logger.info("reading data");
            for (; ; ) {
              byte[] data = new byte[state.getMtu() - 26];
              int br = input.read(data);
              if (br == -1) {
                break;
              }
              ServiceInfoKeyValuePair kv = new ServiceInfoKeyValuePair();
              kv.setKeyName(FdoSys.WRITE);

              if (br < data.length) {
                byte[] temp = data;
                data = new byte[br];
                System.arraycopy(temp, 0, data, 0, br);
              }
              kv.setValue(Mapper.INSTANCE.writeValue(data));
              extra.getQueue().add(kv);
            }
          }
        }
      }
    } catch (Exception e) {
      logger.error("failed to get http content" + e.getMessage());
      throw new InternalServerErrorException(e);
    }
    logger.info("http content downloaded successfully!");

  }

  protected void getFile(ServiceInfoModuleState state,
      FdoSysModuleExtra extra,
      FdoSysInstruction instruction)
      throws IOException {

    ServiceInfoKeyValuePair kv = new ServiceInfoKeyValuePair();
    kv.setKeyName(FdoSys.FILEDESC);
    kv.setValue(Mapper.INSTANCE.writeValue(instruction.getFileDesc()));
    extra.getQueue().add(kv);

    String resource = instruction.getResource();
    if (resource.startsWith("https://") || resource.startsWith("http://")) {
      getUrlFile(state, extra, instruction);
    } else {
      getDbFile(state, extra, instruction);
    }
  }
}
