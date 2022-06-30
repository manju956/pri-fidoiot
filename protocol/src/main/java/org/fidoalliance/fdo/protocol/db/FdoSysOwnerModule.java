// Copyright 2022 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package org.fidoalliance.fdo.protocol.db;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystemException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.sql.Blob;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.util.JSONPObject;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.*;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.fidoalliance.fdo.protocol.*;
import org.fidoalliance.fdo.protocol.dispatch.ServiceInfoModule;
import org.fidoalliance.fdo.protocol.dispatch.ServiceInfoSendFunction;
import org.fidoalliance.fdo.protocol.entity.SystemPackage;
import org.fidoalliance.fdo.protocol.entity.SystemResource;
import org.fidoalliance.fdo.protocol.message.AnyType;
import org.fidoalliance.fdo.protocol.message.DevModList;
import org.fidoalliance.fdo.protocol.message.EotResult;
import org.fidoalliance.fdo.protocol.message.ServiceInfoKeyValuePair;
import org.fidoalliance.fdo.protocol.message.ServiceInfoModuleState;
import org.fidoalliance.fdo.protocol.message.ServiceInfoQueue;
import org.fidoalliance.fdo.protocol.message.StatusCb;
import org.fidoalliance.fdo.protocol.serviceinfo.DevMod;
import org.fidoalliance.fdo.protocol.serviceinfo.FdoSys;
import org.h2.util.json.JSONObject;
import org.h2.util.json.JSONString;
import org.hibernate.Session;
import org.hibernate.Transaction;

/**
 * Implements FdoSysModule spec.
 */
public class FdoSysOwnerModule implements ServiceInfoModule {


  public FdoSysOwnerModule(){
    varMap = new HashMap<>();
  }
  private Map<String, Object> varMap;

  private LoggerService logger = new LoggerService(FdoSysOwnerModule.class);
  private Map<String, byte[]> SVI_MAP = new HashMap<>();

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
    logger.info("in receive()::FdoSysOwnerModule...... \n\n\n");
    FdoSysModuleExtra extra = state.getExtra().covertValue(FdoSysModuleExtra.class);
    switch (kvPair.getKey()) {
      case DevMod.KEY_MODULES: {
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
        extra.getFilter().put(kvPair.getKey(),
            Mapper.INSTANCE.readValue(kvPair.getValue(), String.class));
        break;
      case FdoSys.STATUS_CB:
        if (state.isActive()) {
          StatusCb status = Mapper.INSTANCE.readValue(kvPair.getValue(), StatusCb.class);
          String mapKey = kvPair.getSviMapKey();

          //send notification of status
          ServiceInfoKeyValuePair kv = new ServiceInfoKeyValuePair();
          kv.setKeyName(FdoSys.STATUS_CB);
          kv.setValue(Mapper.INSTANCE.writeValue(status));
          extra.getQueue().add(kv);
          onStatusCb(state, extra, status, mapKey);
          if (status.isCompleted()) {
            // check for error
            if (status.getRetCode() != 0) {
              throw new InternalServerErrorException("Exec_cb status returned failure.");
            }
            extra.setWaiting(false);
            extra.getQueue().addAll(extra.getWaitQueue());
            extra.setWaitQueue(new ServiceInfoQueue());
          }
        }
        break;
      case FdoSys.DATA: {
        logger.info("\nFDO SYS message is DATA\n\n");
        if (state.isActive()) {
          byte[] data = Mapper.INSTANCE.readValue(kvPair.getValue(), byte[].class);
          String sviMapKey = kvPair.getSviMapKey();
          onFetch(state, extra, data, sviMapKey);
        }
      }
      break;
      case FdoSys.EOT:
        logger.info("\nFDO SYS message is EOT\n");
        if (state.isActive()) {
          extra.setWaiting(false);
          extra.setQueue(extra.getWaitQueue());
          extra.setWaitQueue(new ServiceInfoQueue());
          EotResult result = Mapper.INSTANCE.readValue(kvPair.getValue(), EotResult.class);
          onEot(state, extra, result);
        }
        break;
      default:
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

  protected void onStatusCb(ServiceInfoModuleState state, FdoSysModuleExtra extra,
      StatusCb status, String mapKey) throws IOException {
    logger.info("status_cb completed " + status.isCompleted() + " retcode "
        + status.getRetCode() + " timeout " + status.getTimeout());
    logger.info("output of cmd execution on owner: " + status.getExecResult());
    if (mapKey.isEmpty()) return;

    // extract SVI map keys from JSON response
    ObjectMapper obj = new ObjectMapper();
    JsonNode result = obj.readTree(status.getExecResult());
    String execResult = result.get(mapKey).toString();

    if (!SVI_MAP.containsKey(mapKey)) {
      SVI_MAP.put(mapKey, execResult.getBytes(StandardCharsets.UTF_8));
    }
  }

  protected void onFetch(ServiceInfoModuleState state, FdoSysModuleExtra extra,
      byte[] data, String sviMapKey) throws IOException {
    logger.warn(new String(data, StandardCharsets.US_ASCII));
    if (SVI_MAP.containsKey(sviMapKey)) {
      logger.warn(new String(SVI_MAP.get(sviMapKey), StandardCharsets.US_ASCII) + "\n");
    }
    // store the result of fetch in map
    SVI_MAP.put(sviMapKey, data);

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
            makeSvcCall(state, extra, instruction);
	  }
        }
      }
      trans.commit();
    } catch (SQLException e) {
      throw new InternalServerErrorException(e);
    } finally {
      session.close();
    }
  }

  protected void makeSvcCall(ServiceInfoModuleState state,
                            FdoSysModuleExtra extra,
                            FdoSysInstruction instruction) throws IOException {
    /**
     * arg 0 -
     * arg 1 -
     */
    String svcUrlArgs[] = instruction.getSvcUrlArgs();

    // Obtain the protocol from arg 0
    String protocolStr = svcUrlArgs[0];
    int protocol = Integer.parseInt(protocolStr);
    SvcCallProtocol x = null;
    for (SvcCallProtocol p : SvcCallProtocol.values())
      if (p.toInteger() == protocol)
        x = p;

    switch (x) {
      case HTTPS:
        makeHttpRestCall(state, extra, svcUrlArgs);
      case FTP:
      case WS:
        break;
    }
  }

  protected void makeHttpRestCall(ServiceInfoModuleState state,
                                  FdoSysModuleExtra extra,
                                  String[] svcUrlArgs) throws IOException{
    try (CloseableHttpClient httpClient = Config.getWorker(ServiceInfoHttpClientSupplier.class)
            .get()) {

      String url = svcUrlArgs[1];
      String httpMethodStr = svcUrlArgs[2];
      String headersStr = svcUrlArgs[3];
      String urlParamsStr = svcUrlArgs[4];
      String bodyStr = svcUrlArgs[5];
      String responseStr = svcUrlArgs[6]; // comma separated values

      String[] responses = {};
      if(responseStr != null){
        responses = responseStr.split(",");
      }

      URIBuilder builder = getBaseBuilder(url);

      if(urlParamsStr != null){
        Map<String, Object> map = new ObjectMapper().readValue(urlParamsStr, new TypeReference<Map<String,Object>>(){});
        for(Map.Entry<String, Object> e : map.entrySet()){
          String inVal = (String)e.getValue();
          String paramVal = (String)varMap.get(inVal);
          builder.setParameter(e.getKey(), paramVal == null ? inVal : paramVal);
        }

      }

      HttpUriRequest httpRequest = null;
      int httpMethod = Integer.parseInt(httpMethodStr);
      switch (httpMethod){
        case FdoSys.SVC_CALL_HTTP_METHOD_GET:
          httpRequest = new HttpGet(builder.build());
          logger.info("HTTP GET method requested for REST endpoint : "+httpRequest.toString());
          break;
        case FdoSys.SVC_CALL_HTTP_METHOD_POST:
          httpRequest = new HttpPost(builder.build());
          logger.info("HTTP POST method requested for REST endpoint : "+url);
          break;
        case FdoSys.SVC_CALL_HTTP_METHOD_PUT:
          httpRequest = new HttpPut(builder.build());
          logger.info("HTTP PUT method requested for REST endpoint : "+url);
          break;
        case FdoSys.SVC_CALL_HTTP_METHOD_DELETE:
          httpRequest = new HttpDelete(builder.build());
          logger.info("HTTP DELETE method requested for REST endpoint : "+url);
          break;
        default:
          logger.error("HTTP method not supported");
      }

      if(headersStr != null){
        Map<String, Object> map = new ObjectMapper().readValue(headersStr, new TypeReference<Map<String,Object>>(){});
        for(Map.Entry<String, Object> e : map.entrySet()){
          String inVal = (String)e.getValue();
          String headerVal = (String)varMap.get(inVal);
          httpRequest.addHeader(e.getKey(), headerVal == null ? inVal : headerVal);
        }
      }

      try (CloseableHttpResponse httpResponse = httpClient.execute(httpRequest);) {
        logger.info(httpResponse.getStatusLine().toString());
        if (httpResponse.getStatusLine().getStatusCode() != 200) {
          throw new InternalServerErrorException(httpResponse.getStatusLine().toString());
        }
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

              if (br < data.length) {
                byte[] temp = data;
                data = new byte[br];
                System.arraycopy(temp, 0, data, 0, br);
                String serialized = new String(temp, StandardCharsets.UTF_8);
                logger.info(serialized);
                // Not taking care of nested object for now. Expects a plain JSON Object.
                Map<String, Object> map = new ObjectMapper().readValue(serialized, new TypeReference<Map<String,Object>>(){});

                for(String k : responses){
                  String val = (String)map.get(k);
                  if(val != null)
                    varMap.put(k, val);
                }
//                for(Map.Entry<String, Object> e : varMap.entrySet())
//                  logger.info("Key : "+e.getKey()+" Value :"+e.getValue());
              }
            }
          }
        }
      }
    } catch (Exception e) {
      logger.error("Failed to make http(s) REST call : " + e.getMessage());
      throw new InternalServerErrorException(e);
    }
    logger.info("HTTP(S) REST call completed successfully!");
  }

  private URIBuilder getBaseBuilder(String url) {
    URIBuilder builder = new URIBuilder();
    builder.setScheme(url.split(":")[0]);
    String url_part = url.split("//")[1];
    String url_sock = url_part.split("/")[0];
    builder.setHost(url_sock.split(":")[0]);
    if(url_sock.contains(":"))
      builder.setPort(Integer.parseInt(url_sock.split(":")[1]));
    builder.setPath(url_part.substring(url_part.indexOf("/"), url_part.length()));

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

    try (CloseableHttpClient httpClient = Config.getWorker(ServiceInfoHttpClientSupplier.class)
        .get()) {

      logger.info("HTTP(S) GET: " + resource);
      HttpGet httpRequest = new HttpGet(resource);
      try (CloseableHttpResponse httpResponse = httpClient.execute(httpRequest);) {
        logger.info(httpResponse.getStatusLine().toString());
        if (httpResponse.getStatusLine().getStatusCode() != 200) {
          throw new InternalServerErrorException(httpResponse.getStatusLine().toString());
        }
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
