from __future__ import annotations
from datetime import datetime
from typing import Any,Mapping,Sequence
TEMPORAL_PRESETS_SECONDS={"off":0,"15m":900,"1h":3600,"6h":21600,"24h":86400,"7d":604800,"30d":2592000,"unlimited":None}
DEFAULT_VISIBILITY_PRESET="unlimited";DEFAULT_TRACK_TAIL_PRESET="unlimited"
def preset_seconds(key:str)->int|None:
 if key not in TEMPORAL_PRESETS_SECONDS:raise ValueError(f"unknown temporal presentation preset: {key}")
 return TEMPORAL_PRESETS_SECONDS[key]
def presentation_epoch(row:Mapping[str,Any])->int|None:
 for k in ("position_epoch","received_epoch"):
  try:
   v=int(row.get(k))
   if v>0:return v
  except (TypeError,ValueError):pass
 for k in ("updated_at","stored_at","received_at"):
  v=row.get(k)
  if not v:continue
  try:return int(datetime.fromisoformat(str(v).replace("Z","+00:00")).timestamp())
  except (TypeError,ValueError,OverflowError):pass
 return None
def _within(r,now,w):
 if w is None:return True
 w=int(w)
 if w<0:raise ValueError("window must not be negative")
 if w==0:return False
 e=presentation_epoch(r)
 return False if e is None else max(0,int(now)-e)<=w
def filter_latest_for_visibility(rows:Sequence[Mapping[str,Any]],*,now_epoch:int,visibility_seconds:int|None)->list[dict[str,Any]]:return [dict(r) for r in rows if _within(r,now_epoch,visibility_seconds)]
def filter_history_for_track_tail(rows:Sequence[Mapping[str,Any]],*,now_epoch:int,track_tail_seconds:int|None)->list[dict[str,Any]]:return [dict(r) for r in rows if _within(r,now_epoch,track_tail_seconds)]
