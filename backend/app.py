from fastapi import FastAPI, APIRouter, Depends, Security, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from operator import itemgetter
from packet_processor import PacketProcessor
from badge_link_controller import BadgeLinkController
from game_logic_controller import GameLogicController
from config import Config
from database import db
from schemas import Station, IrPacketRequestSchema, Display, ScoreEntry, ReCTFSolves, ReCTFScoreSchema, BadgeLinkSchema

config = Config("config.yaml")

stations = db["stations"]

app = FastAPI()
packet_processor_instance = PacketProcessor(config=config)

router = APIRouter(prefix="/v1")
security = HTTPBearer()

async def get_station(credentials: HTTPAuthorizationCredentials = Security(security)) -> Station:
    key = credentials.credentials

    station = await stations.find_one({"station_key": key})
    if station is None:
        raise HTTPException(status_code=403, detail="Invalid station key")

    return Station(**station)

# TODO: process remaining rx packets before starting the backend

@app.get("/")
async def read_root():
    return {"message": "Hello World"}

## ====== Public API Endpoints ======
@app.get("/api/scores")
async def get_scoreboard() -> list[ScoreEntry]:
    scoreboard = await GameLogicController.get_user_scoreboard()

    for score_entry in scoreboard:
        score_entry["name"] = " ".join(map(lambda x: f"{x:02x}", int.to_bytes(score_entry["player_id"], 4, 'little')))

    scoreboard.sort(key=itemgetter("total_score"), reverse=True)

    return scoreboard


@app.get("/api/stations")
async def get_stations_scores():
    data = {}

    async for station_id, score in GameLogicController.get_stations_scores():
        data[station_id] = score

    return data


## ====== Station API Endpoints ======
@router.get("/tx")
async def tx(station: Station = Depends(get_station)) -> list[IrPacketRequestSchema]:
    # Backend asks the base station to send a packet.
    packets = packet_processor_instance.has_packet_for_tx(station)

    ret = []
    async for packet in packets:
        ret.append(packet)

    return ret


@router.post("/rx")
async def rx(ir_packet: IrPacketRequestSchema, station: Station = Depends(get_station)):
    # Base station received a packet, sending it to the backend.
    try:
        await packet_processor_instance.on_receive_packet(ir_packet, station)
    except Exception as e:
        print(f"Error processing packet: {e}")
        raise HTTPException(status_code=500, detail=str(e))

    return {"status": "ok"}


@router.get("/station-display")
async def station_display(station: Station = Depends(get_station)) -> Display:
    return station.display


@router.get("/station-score")
async def get_history(station: Station = Depends(get_station)):
    # Fetch the history of packets for the station
    history = await GameLogicController.get_station_score(station.station_id)
    return history


## ====== ReCTF API Endpoints ======
@app.post("/rectf/score")
async def receive_rectf_score(schema: ReCTFScoreSchema, credentials: HTTPAuthorizationCredentials = Security(security)):
    # Validate ReCTF key
    if credentials.credentials != config.get('rectf', {}).get('api_key'):
        raise HTTPException(status_code=403, detail="Invalid key")

    user = await BadgeLinkController.translate_uid_to_user(schema.uid)

    # Process the ReCTF score for the user
    await GameLogicController.apply_rectf_score(schema.uid, user, schema.solves)

    return {"status": "ok"}


## ====== Badge Linking API Endpoints ======
@app.get("/hitcon/link")
async def get_hitcon_linkage(credentials: HTTPAuthorizationCredentials = Security(security)):
    """
    Get the current badge linkage between the attendee.
    """
    # Validate attendee token
    if not credentials.credentials:
        raise HTTPException(status_code=400, detail="Missing token")

    uid, name = await BadgeLinkController.parse_badge_token(credentials.credentials)

    if not uid:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Get the badge user linked to the UID
    badge_user = await BadgeLinkController.translate_uid_to_user(uid)

    return {"badge_user": badge_user, "name": name}


@app.post("/hitcon/link")
async def hitcon_link(schema: BadgeLinkSchema, credentials: HTTPAuthorizationCredentials = Security(security)):
    """
    Link the badge with the attendee.
    """
    # Validate attendee token
    if not credentials.credentials:
        raise HTTPException(status_code=400, detail="Missing token")

    uid, name = await BadgeLinkController.parse_badge_token(credentials.credentials)

    if not uid:
        raise HTTPException(status_code=401, detail="Invalid token")

    if not schema.badge_user:
        raise HTTPException(status_code=422, detail="badge_user is required")

    # Link the badge with the attendee
    try:
        old_badge_user, _ = await BadgeLinkController.link_badge_with_attendee(uid, schema.badge_user, name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if old_badge_user is not None:
        # remove old badge buff
        await GameLogicController.apply_rectf_score(uid, old_badge_user, ReCTFSolves(a=0, b=0))

    # apply rectf buff to the new badge
    await GameLogicController.apply_rectf_score(uid, schema.badge_user)

    return {"status": "ok"}


app.include_router(router)
