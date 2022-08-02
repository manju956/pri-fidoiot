package org.fidoalliance.fdo.protocol;

public enum SvcCallProtocol {
  HTTPS(0),
  GRPC(1),
  FTP(2),
  WS(3);

  private int id;

  SvcCallProtocol(int id) {
    this.id = id;
  }

  public int toInteger() {
    return id;
  }
}
