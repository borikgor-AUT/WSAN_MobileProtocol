var END_TIME_MS = 1200000000 // 1200s = 20 min

function handleLocationRequest(mote) {
  var pos = mote.getInterfaces().getPosition();
  var ts_ms = Math.floor(time / 1000);
  var x = pos.getXCoordinate();
  var y = pos.getYCoordinate();
  var mid = mote.getID();
  var response = "LOC " + mid + " "
               + Math.round(10 * x) + " "
               + Math.round(10 * y) + " "
               + ts_ms;
  mote.getInterfaces().get("Serial").writeString(response + "\n");
}

while (true) {
  YIELD();

  if (time >= END_TIME_MS) {
      log.log("Time " + time + " limit reached, script exiting\n");
    break;
  }

  if (typeof msg === "string") {
    var s = msg.trim();
    var mote = sim.getMoteWithID(id);
    if (s === "REQ_LOC" && mote != null) {
      handleLocationRequest(mote);
    }
  }
}
