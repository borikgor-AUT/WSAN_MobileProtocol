/* ============================================================================
 * Cooja Simulation Script: Highway Motes — Parity-based bidirectional lanes
 *
 * WHAT THIS SCRIPT DOES
 * - Classify motes into Stationary (incl. RSU) and Mobile.
 * - INITIAL PLACEMENT (UPDATED):
 *   * Stationary motes are placed on X axis at s * STATIONARY_SPACING.
 *   * Mobile motes are distributed near StationARY motes in round-robin:
 *       baseX = stationaryX[k % stationaryCount]
 *       spread = STATIONARY_SPACING / 100
 *       odd IDs move RIGHT (+), even IDs move LEFT (-)
 * - MOVEMENT:
 *   * Continuous motion along X. When hitting bounds, reverse direction.
 *   * Even: From 0 to MAX_X and back; Odd:  From MAX_X to 0 and back;
 * - LED MONITOR (kept): If RED LED is ON, freeze the mote (auto-stop).
 * - STOP/GO (kept) and REQ_LOC handler (kept).
 * ========================================================================== */

/* -------------------------- Parameters ------------------------------------ */
var STATIONARY_SPACING = 2000;
var MAX_X = 10000; /* absolute bound along X axis */
var MAX_Y = 100; /* unused for now (we keep Y=0) */
var SIMULATION_TICK_DELAY = 500; /* ms-equivalent (Cooja uses /10) */
var SPEED_MIN = 16; /* absolute magnitude lower bound */
var SPEED_MAX = 28; /* absolute magnitude upper bound */
var DELTA_SPEED = 0.5; /* small jitter per tick */

/* Spread around RSUs (requested): */
var START_SPREAD = STATIONARY_SPACING / 100;

/* -------------------------- State containers ------------------------------ */
var stationaryMotes = [];
var mobileMotes = [];

/* Per-mobile state, indexed by the mobileMotes' index (not mote ID) */
var moteSpeedAbs = []; /* absolute speed magnitude (>=0) */
var moteSpeedSign = []; /* +1 to the right, -1 to the left */
var moteDistance = []; /* distance accumulator (for optional events) */

/* Control maps by mote ID */
var frozen = {}; /* STOP-hard-freeze */
var stoppedManual = {}; /* was stopped manually at least once */
var ledIgnore = {}; /* ignore RED LED after GO until LED becomes OFF */

/* -------------------------- Init: classify and place ---------------------- */
log.log("Initializing motes (round-robin near RSUs, parity directions)...\n");
var motes = sim.getMotes();
for (var i = 0; i < motes.length; i++) {
  var m = motes[i];
  var name = m.getType().getDescription();
  if (name.indexOf("Stationary") !== -1 || name.indexOf("RSU") !== -1) {
    stationaryMotes.push(m);
  } else if (name.indexOf("Mobile") !== -1) {
    mobileMotes.push(m);
  } else {
    log.log("Warn: Unclassified mote " + m.getID() + ": " + name + "\n");
  }
}

/* Place stationary motes on X axis (Y=0), as before */
for (var s = 0; s < stationaryMotes.length; s++) {
  var sm = stationaryMotes[s];
  var x = s * STATIONARY_SPACING;
  sm.getInterfaces().getPosition().setCoordinates(x, 0, 0);
}

/* Build a list of stationary X positions (after placement) */
var rsuXs = [];
for (var s2 = 0; s2 < stationaryMotes.length; s2++) {
  var p2 = stationaryMotes[s2].getInterfaces().getPosition();
  rsuXs.push(p2.getXCoordinate());
}
var rsuCount = rsuXs.length;
if (rsuCount === 0) {
  log.log("ERROR: No stationary/RSU motes found. Script cannot place mobiles.\n");
}

/* Round-robin initial placement for mobiles near RSUs */
for (var k = 0; k < mobileMotes.length; k++) {
  var mm = mobileMotes[k];
  var mid = mm.getID();
  var pos = mm.getInterfaces().getPosition();

  /* Direction: odd -> RIGHT, even -> LEFT */
  var sign = ((mid % 2) === 1) ? +1 : -1; /* odd right, even left */

  /* Round-robin RSU assignment */
  var base = rsuXs[k % rsuCount];

  /* Offset pattern so motes don't stack at exactly same coordinate.
     Also bias slightly opposite to movement, so they cross the RSU. */
  var bucket = Math.floor(k / rsuCount);           /* 0,1,2... */
  var slot = (bucket % 5) - 2;                     /* -2,-1,0,+1,+2 */
  var jitter = (Math.random() - 0.5) * START_SPREAD; /* +/- spread/2 */
  var bias = -sign * START_SPREAD;                 /* start slightly before RSU */
  var startX = base + bias + slot * START_SPREAD + jitter;

  /* Clamp into current highway bounds (0..MAX_X) */
  if (startX < 0) startX = 0;
  if (startX > MAX_X) startX = MAX_X;

  pos.setCoordinates(startX, 0, 0);

  /* absolute speed in [SPEED_MIN, SPEED_MAX] */
  var vabs = SPEED_MIN + Math.random() * (SPEED_MAX - SPEED_MIN);
  moteSpeedAbs[k] = vabs;
  moteSpeedSign[k] = sign;
  moteDistance[k] = 0;
}

/* Movement scheduler */
function scheduleNextMove() {
  GENERATE_MSG(SIMULATION_TICK_DELAY / 10, "move_next");
}
scheduleNextMove();

/* -------------------------- Helpers --------------------------------------- */
/* Answer "REQ_LOC" with current X,Y in decimeters and ts in ms */
function handleLocationRequest(mote) {
  var pos = mote.getInterfaces().getPosition();
  var ts_ms = Math.floor(time / 1000);
  var x = pos.getXCoordinate();
  var y = pos.getYCoordinate();
  var mid = mote.getID();
  var response = "LOC " + mid + " " + Math.round(10 * x) + " "
    + Math.round(10 * y) + " " + ts_ms;
  mote.getInterfaces().get("Serial").writeString(response + "\n");
}

/* Get RED LED state defensively */
function isRedOn(mote) {
  var leds = mote.getInterfaces().getLED ? mote.getInterfaces().getLED() : null;
  if (!leds || !leds.isRedOn) return false;
  try { return leds.isRedOn(); } catch (e) { return false; }
}

/* -------------------------- Main loop ------------------------------------- */
while (true) {
  YIELD();

  /* ===================== Commands via Serial (STOP/GO/REQ_LOC) ============= */
  if (typeof msg === "string") {
    var s = ("" + msg).trim();
    var src = sim.getMoteWithID(id);

    /* STOP <id> : hard freeze */
    var mStop = s.match(/^STOP\s+(\d+)$/i);
    if (mStop) {
      var stopId = parseInt(mStop[1], 10);
      frozen[stopId] = true;
      stoppedManual[stopId] = true;
      if (src && src.getInterfaces().get("Serial")) {
        src.getInterfaces().get("Serial").writeString("OK: STOP " + stopId + "\n");
      }
      continue;
    }

    /* GO <id> : unfreeze, send "GO\n", and temporarily ignore that mote's LED */
    var mGo = s.match(/^GO\s+(\d+)$/i);
    if (mGo) {
      var goId = parseInt(mGo[1], 10);
      delete frozen[goId];
      if (stoppedManual[goId]) { ledIgnore[goId] = true; }
      var tgt = sim.getMoteWithID(goId);
      if (tgt && tgt.getInterfaces().get("Serial")) {
        tgt.getInterfaces().get("Serial").writeString("GO\n");
      }
      if (src && src.getInterfaces().get("Serial")) {
        src.getInterfaces().get("Serial").writeString("OK: GO " + goId + "\n");
      }
      continue;
    }

    /* REQ_LOC from a mote -> answer */
    if (s.indexOf("REQ_LOC") >= 0) {
      var reqMote = sim.getMoteWithID(id);
      if (reqMote) handleLocationRequest(reqMote);
      continue;
    }
  }

  /* ===================== Movement tick ==================================== */
  if (typeof msg === "string" && msg === "move_next") {
    for (var i = 0; i < mobileMotes.length; i++) {
      var mote = mobileMotes[i];
      var mid = mote.getID();
      var pos = mote.getInterfaces().getPosition();
      var x = pos.getXCoordinate();

      /* 1) Manual hard freeze overrides everything */
      if (frozen[mid]) {
        pos.setCoordinates(x, 0, 0);
        moteDistance[i] = 0;
        continue;
      }

      /* 2) LED-monitor (kept) */
      var red = isRedOn(mote);
      if (red && !ledIgnore[mid]) {
        moteSpeedAbs[i] = 0;
        pos.setCoordinates(x, 0, 0);
        moteDistance[i] = 0;
        continue;
      }
      if (!red && ledIgnore[mid]) {
        delete ledIgnore[mid];
      }

      /* 3) Speed jitter (on absolute value), keep sign separately */
      var vabs = moteSpeedAbs[i] + (Math.floor(Math.random() * 3) - 1) * DELTA_SPEED;
      if (vabs < SPEED_MIN) vabs = SPEED_MIN;
      if (vabs > SPEED_MAX) vabs = SPEED_MAX;
      moteSpeedAbs[i] = vabs;

      /* 4) Advance along X per current sign */
      var dx = vabs * moteSpeedSign[i];
      x += dx;
      moteDistance[i] += Math.abs(dx);

      /* 5) Bounce on boundaries: reverse sign if outside limits */
      if (x > MAX_X) { x = MAX_X; moteSpeedSign[i] = -1; }
      if (x < 0) { x = 0; moteSpeedSign[i] = +1; }

      pos.setCoordinates(x, 0, 0);
    }
    scheduleNextMove();
    continue;
  }
}