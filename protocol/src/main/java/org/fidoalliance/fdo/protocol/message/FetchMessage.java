package org.fidoalliance.fdo.protocol.message;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.fidoalliance.fdo.protocol.serialization.GenericArraySerializer;

@JsonFormat(shape = JsonFormat.Shape.ARRAY)
@JsonPropertyOrder({"data", "svi_map_key"})
@JsonSerialize(using = GenericArraySerializer.class)
public class FetchMessage {
  @JsonProperty("data")
  byte[] data;

  @JsonProperty("svi_map_key")
  String sviMapKey;

  public byte[] getDataBytes() {
    return data;
  }

  public String getSviMapKey() {
    return sviMapKey;
  }

  public void setDataBytes(byte[] data) {
    this.data = data;
  }

  public void setSviMapKey(String sviMapKey) {
    this.sviMapKey = sviMapKey;
  }
}

