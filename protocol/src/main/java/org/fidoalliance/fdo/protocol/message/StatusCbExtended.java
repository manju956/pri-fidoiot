package org.fidoalliance.fdo.protocol.message;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.fidoalliance.fdo.protocol.serialization.GenericArraySerializer;

@JsonFormat (shape = JsonFormat.Shape.ARRAY)
@JsonPropertyOrder ({"completed", "retCode", "timeout", "execResult", "svi_map_key"})
@JsonSerialize (using = GenericArraySerializer.class)
public class StatusCbExtended extends StatusCb {
  @JsonProperty ("execResult")
  String execResult;

  @JsonProperty ("svi_map_key")
  String sviMapKey;

  public void setExecResult(String execResult) {
    this.execResult = execResult;
  }

  public String getExecResult() {
    return execResult;
  }

  public String getSviMapKey() {
    return sviMapKey;
  }

  public void setSviMapKey(String sviMapKey) {
    this.sviMapKey = sviMapKey;
  }
}
