"""Wardriving 2.0 — clustering de BSSID→localização provável.

Dado o scan geolocalizado do ``WiFiScanner``, agrupa BSSIDs por célula
de grelha (binning) para mapear cobertura de redes numa área. Útil para
red teams planearem deploys de rogue APs ou entender a topologia do alvo.

Sem ML pesado: binning por grelha + centroide por grupo (média dos pontos).
Se quiseres clustering real, troca ``cluster_grid`` por k-means (sklearn).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class APCluster:
    bssid: str
    count: int = 0
    lat_sum: float = 0.0
    lon_sum: float = 0.0
    ssid: str = ""

    @property
    def centroid(self) -> tuple[float, float]:
        if self.count == 0:
            return (0.0, 0.0)
        return (self.lat_sum / self.count, self.lon_sum / self.count)


def cluster_grid(observations: list[dict[str, Any]], cell_meters: float = 25.0) -> list[APCluster]:
    """Bin observations of (bssid, lat, lon) into a coverage map.

    ``observations`` are dicts with keys ``bssid``, ``ssid``, ``lat``, ``lon``.
    """
    # ~111_320 m per degree latitude; use it to convert meters -> degrees
    deg = cell_meters / 111_320.0
    bins: dict[str, APCluster] = {}

    for obs in observations:
        bssid = obs.get("bssid")
        lat = obs.get("lat")
        lon = obs.get("lon")
        if not bssid or lat is None or lon is None:
            continue
        # grid cell key (rounded to cell size)
        key = f"{round(lat / deg)},{round(lon / deg)}"
        if key not in bins:
            bins[key] = APCluster(bssid=bssid, ssid=obs.get("ssid", ""))
        c = bins[key]
        c.count += 1
        c.lat_sum += lat
        c.lon_sum += lon
        if not c.ssid and obs.get("ssid"):
            c.ssid = obs["ssid"]

    return list(bins.values())


def coverage_report(
    observations: list[dict[str, Any]], cell_meters: float = 25.0
) -> dict[str, Any]:
    clusters = cluster_grid(observations, cell_meters=cell_meters)
    return {
        "cells": len(clusters),
        "total_observations": len(observations),
        "aps": [
            {
                "bssid": c.bssid,
                "ssid": c.ssid,
                "observations": c.count,
                "centroid": {"lat": c.centroid[0], "lon": c.centroid[1]},
            }
            for c in clusters
        ],
    }
