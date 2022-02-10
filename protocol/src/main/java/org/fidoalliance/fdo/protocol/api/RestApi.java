package org.fidoalliance.fdo.protocol.api;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.fidoalliance.fdo.protocol.BufferUtils;
import org.fidoalliance.fdo.protocol.HttpUtils;
import org.fidoalliance.fdo.protocol.db.HibernateUtil;
import org.hibernate.Session;
import org.hibernate.Transaction;
import org.hibernate.resource.transaction.spi.TransactionStatus;

public class RestApi implements AutoCloseable {

  private static final int READ_SIZE = 1024;
  private HttpServletRequest request;
  private HttpServletResponse response;
  private List<String> uriSegments = new ArrayList<>();

  private Session session;
  private Transaction transaction;


  protected String getResponseContentType() {
    return HttpUtils.HTTP_PLAIN_TEXT;
  }

  protected String getRequestContentType() {
    return HttpUtils.HTTP_PLAIN_TEXT;
  }

  protected HttpServletRequest getRequest() {
    return request;
  }

  protected String getParamByValue(String value) {
    return request.getParameter(value);
  }

  protected int getReadSize() {
    return READ_SIZE;
  }
  protected int getMaxMessageSize() {
    return BufferUtils.getMaxBufferSize()*2;
  }

  protected HttpServletResponse getResponse() {
    return response;
  }

  protected List<String> getUriSegments() {
    return uriSegments;
  }

  protected Session getSession() {
    if (session == null) {
      session = HibernateUtil.getSessionFactory().openSession();
    }
    return session;
  }

  protected Transaction getTransaction() {
    if (transaction == null) {
      transaction = getSession().beginTransaction();
    }
    return transaction;
  }

  protected void commit() {
    if (transaction != null ) {
      if (transaction.getStatus() == TransactionStatus.ACTIVE) {
        transaction.commit();
      }
      transaction = null;
    }
  }

  protected String getStringBody() throws Exception {
    StringBuilder builder = new StringBuilder();
    try {
      //we don't close streams per servlet api
      final InputStreamReader reader =
          new InputStreamReader(getRequest().getInputStream(), StandardCharsets.UTF_8);

      StringWriter stringWriter = new StringWriter();
      reader.transferTo(stringWriter);
      return stringWriter.toString();
    } catch (IOException e) {
      throw new InternalServerErrorException(e);
    }
  }


  protected void init(HttpServletRequest req, HttpServletResponse resp)
      throws UnsupportedMediaTypeException, NotFoundException {
    this.request = req;
    this.response = resp;
    if (!request.getContentType().equals(getRequestContentType())) {
      throw new UnsupportedMediaTypeException(req.getContentType());
    }

    File file = new File(req.getRequestURI());

    while (file != null) {
      String name = file.getName();
      if (name.equals(".") || name.equals("..")) {
        throw new NotFoundException(name);
      }
      uriSegments.add(name);
      file = file.getParentFile();
    }
  }

  protected String getLastSegment() throws NotFoundException {
    if (uriSegments.size() > 0) {
      return uriSegments.get(0);
    }
    throw new NotFoundException(getRequest().getRequestURI());
  }

  protected void doDelete() throws Exception  {
  }

  protected void doPut() throws Exception {

  }

  protected void doGet() throws Exception {
  }

  protected void doPost() throws Exception {
  }

  @Override
  public void close() throws Exception {
    commit();
    if (session != null) {
        session.close();
    }
  }
}
