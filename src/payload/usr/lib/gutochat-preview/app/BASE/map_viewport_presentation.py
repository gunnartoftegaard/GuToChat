from __future__ import annotations
import math
from collections import defaultdict
from typing import Any, Mapping, Sequence

def xyz_tile_bounds(zoom:int,x:int,y:int)->tuple[float,float,float,float]:
    n=1<<int(zoom)
    west=float(x)/n*360.0-180.0
    east=float(x+1)/n*360.0-180.0
    north=math.degrees(math.atan(math.sinh(math.pi*(1.0-2.0*float(y)/n))))
    south=math.degrees(math.atan(math.sinh(math.pi*(1.0-2.0*float(y+1)/n))))
    return west,south,east,north

def filter_rows_to_xyz_tile(rows:Sequence[Mapping[str,Any]],*,zoom:int,x:int,y:int)->list[dict[str,Any]]:
    west,south,east,north=xyz_tile_bounds(zoom,x,y)
    out=[]
    for row in rows:
        try:
            lat=float(row.get('latitude')); lon=float(row.get('longitude'))
        except (TypeError,ValueError):
            continue
        if south <= lat <= north and west <= lon <= east:
            out.append(dict(row))
    return out

def group_history_tracks(rows:Sequence[Mapping[str,Any]])->list[list[dict[str,Any]]]:
    groups=defaultdict(list)
    for row in rows:
        key=(str(row.get('map_layer') or ''),str(row.get('network') or ''),str(row.get('node_id') or row.get('node_label') or ''))
        groups[key].append(dict(row))
    def epoch(r):
        for k in ('position_epoch','received_epoch'):
            try:return int(r.get(k) or 0)
            except (TypeError,ValueError):pass
        return 0
    return [sorted(items,key=epoch) for _,items in sorted(groups.items()) if len(items)>=2]
