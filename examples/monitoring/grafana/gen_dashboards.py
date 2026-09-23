#!/usr/bin/env python3
"""Generates the Grafana dashboards of the etr monitoring example.

    python3 gen_dashboards.py [output dir]   # default: dashboards/ next to this file

etr-overview.json   every target (source -> destination) at a glance
etr-dashboard.json  deep dive into one target: topology, paths, hops, flows
etr-fleet.json      every site: site x site matrices, worst targets, shared hops

The JSON files are generated: edit this script and rerun it instead of editing
them. Grafana reloads provisioned dashboards within 10 seconds. Only the Python
standard library is needed.
"""

import json
import os
import sys

PROM = {"type": "prometheus", "uid": "prometheus"}
INF = {"type": "yesoreyeram-infinity-datasource", "uid": "infinity"}
EXPORTER = "http://etr-exporter:8080"

# Deep dive: one target, optionally narrowed to some flows.
F = 'source="$source", destination="$destination", src_port=~"$src_port"'
FH = F + ', hop_ip!="*"'
# Overview: all targets, optionally narrowed by source.
FO = 'source=~"$source"'
BY_TARGET = "sum by (source, destination)"
TARGET = "{{source}} → {{destination}}"
DEEP_DIVE = "/d/etr-paths"
OVERVIEW = "/d/etr-overview"

DEEP_DIVE_PARAMS = [
    {"key": "source", "value": "${source}"},
    {"key": "destination", "value": "${destination}"},
    {"key": "src_port", "value": "${src_port:csv}"},
]
OVERVIEW_PARAMS = [{"key": "source", "value": "${source:csv}"}]

_id = 0


def pid():
    global _id
    _id += 1
    return _id


def prom(expr, legend="", ref="A", **kw):
    t = {"datasource": PROM, "expr": expr, "legendFormat": legend, "refId": ref, "range": True}
    t.update(kw)
    return t


def inf(path, ref="A", columns=None, params=None):
    return {
        "datasource": INF,
        "refId": ref,
        "type": "json",
        "source": "url",
        "format": "table",
        "parser": "backend",
        "url": EXPORTER + path,
        "url_options": {
            "method": "GET",
            "data": "",
            "params": (DEEP_DIVE_PARAMS if params is None else params)
            + [
                {"key": "from", "value": "${__from}"},
                {"key": "to", "value": "${__to}"},
            ],
        },
        "root_selector": "",
        "columns": columns or [],
        "filters": [],
    }


def col(selector, text, typ="string"):
    return {"selector": selector, "text": text, "type": typ}


def panel(typ, title, x, y, w, h, targets, desc="", **kw):
    p = {
        "id": pid(),
        "type": typ,
        "title": title,
        "description": desc,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "datasource": targets[0]["datasource"] if targets else PROM,
        "targets": targets,
    }
    p.update(kw)
    return p


def row(title, y):
    return {
        "id": pid(),
        "type": "row",
        "title": title,
        "collapsed": False,
        "gridPos": {"x": 0, "y": y, "w": 24, "h": 1},
        "panels": [],
    }


def thresholds(*steps):
    out = [{"color": steps[0], "value": None}]
    for i in range(1, len(steps), 2):
        out.append({"color": steps[i + 1], "value": steps[i]})
    return {"mode": "absolute", "steps": out}


LOSS_T = thresholds("green", 1, "orange", 5, "red")


def stat(title, x, expr, unit, desc, th=None, decimals=None, color_mode="value", y=1, w=4):
    defaults = {"unit": unit, "color": {"mode": "thresholds"}, "thresholds": th or thresholds("blue")}
    if decimals is not None:
        defaults["decimals"] = decimals
    return panel(
        "stat",
        title,
        x,
        y,
        w,
        4,
        [prom(expr, instant=True, range=False)],
        desc,
        fieldConfig={"defaults": defaults, "overrides": []},
        options={
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "colorMode": color_mode,
            "graphMode": "none",
            "textMode": "value",
            "justifyMode": "center",
            "orientation": "auto",
            "wideLayout": True,
            "showPercentChange": False,
        },
    )


def timeseries(title, x, y, w, h, targets, unit, desc="", overrides=None, links=None, legend_calcs=None, **custom):
    c = {
        "drawStyle": "line",
        "lineWidth": 1,
        "fillOpacity": 8,
        "showPoints": "never",
        "spanNulls": False,
        "gradientMode": "none",
        "axisSoftMin": 0,
    }
    c.update(custom)
    return panel(
        "timeseries",
        title,
        x,
        y,
        w,
        h,
        targets,
        desc,
        fieldConfig={
            "defaults": {"unit": unit, "color": {"mode": "palette-classic"}, "custom": c, "links": links or []},
            "overrides": overrides or [],
        },
        options={
            "legend": {
                "displayMode": "table",
                "placement": "right",
                "calcs": legend_calcs or ["mean", "max", "lastNotNull"],
                "showLegend": True,
                "sortBy": "Mean",
                "sortDesc": True,
            },
            "tooltip": {"mode": "multi", "sort": "desc"},
        },
    )


def by_name(name, *props):
    return {"matcher": {"id": "byName", "options": name}, "properties": [{"id": k, "value": v} for k, v in props]}


def table(title, x, y, w, h, target, desc, overrides, sort=None):
    # The Infinity backend parser returns columns sorted by name; restore the declared order.
    order = {c["text"]: i for i, c in enumerate(target["columns"])}
    return panel(
        "table",
        title,
        x,
        y,
        w,
        h,
        [target],
        desc,
        transformations=[{"id": "organize", "options": {"indexByName": order}}],
        fieldConfig={
            "defaults": {"custom": {"align": "auto", "filterable": True, "cellOptions": {"type": "auto"}}},
            "overrides": overrides,
        },
        options={
            "showHeader": True,
            "cellHeight": "sm",
            "footer": {"show": False, "reducer": ["sum"], "fields": ""},
            "sortBy": sort or [],
        },
    )


def loss_cell(name):
    return by_name(
        name,
        ("unit", "percent"),
        ("decimals", 1),
        ("thresholds", LOSS_T),
        ("custom.cellOptions", {"type": "color-text"}),
    )


def long_cell(name, width=None):
    props = [("custom.inspect", True)]
    if width:
        props.append(("custom.width", width))
    return by_name(name, *props)


def ms_cell(name, label):
    return by_name(name, ("displayName", label), ("unit", "ms"), ("decimals", 1))


PATH_COLORS = [
    "green",
    "blue",
    "orange",
    "purple",
    "yellow",
    "red",
    "#56A64B",
    "#3274D9",
    "#FF780A",
    "#A352CC",
    "#F2CC0C",
    "#E02F44",
]
path_mappings = [
    {
        "type": "value",
        "options": {str(i + 1): {"text": f"#{i + 1}", "color": PATH_COLORS[i], "index": i} for i in range(12)},
    }
]


def deep_dive():
    panels = []

    # --- Summary --------------------------------------------------------------
    panels.append(row("Summary", 0))
    panels.append(
        panel(
            "stat",
            "Target",
            0,
            1,
            6,
            4,
            [
                prom(
                    'max by (destination, destination_ptr) (etr_destination_info{destination="$destination"})',
                    "{{destination_ptr}}",
                    instant=True,
                    range=False,
                )
            ],
            "Reverse DNS name of the destination, as reported by etr (empty without PTR records).",
            fieldConfig={"defaults": {"color": {"mode": "fixed", "fixedColor": "text"}}, "overrides": []},
            options={
                "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                "colorMode": "value",
                "graphMode": "none",
                "textMode": "name",
                "justifyMode": "center",
                "orientation": "auto",
                "wideLayout": True,
                "showPercentChange": False,
            },
        )
    )
    panels += [
        stat(
            "End-to-end loss",
            6,
            f"clamp_min(100 * (1 - sum(increase(etr_destination_reached_total{{{F}}}[1m]))"
            f" / (sum(increase(etr_probe_runs_total{{{F}}}[1m])) > 0)), 0)",
            "percent",
            "Share of probes that did not get a reply from the destination over the last minute.",
            LOSS_T,
            1,
            w=3,
        ),
        stat(
            "Median RTT",
            9,
            f"histogram_quantile(0.5, sum by (le) (rate(etr_destination_rtt_seconds_bucket{{{F}}}[1m])))",
            "s",
            "Median end-to-end RTT over the last minute, all selected flows.",
            w=3,
        ),
        stat(
            "p95 RTT",
            12,
            f"histogram_quantile(0.95, sum by (le) (rate(etr_destination_rtt_seconds_bucket{{{F}}}[1m])))",
            "s",
            "95th percentile end-to-end RTT over the last minute.",
            w=3,
        ),
        stat(
            "Jitter",
            15,
            f"avg(etr_destination_jitter_seconds{{{F}}})",
            "s",
            "Smoothed RTT variation between consecutive probes (RFC 3550 style), averaged over flows.",
            w=3,
        ),
        stat(
            "Paths in use",
            18,
            'sum(etr_destination_active_paths{source="$source", destination="$destination"})',
            "none",
            "Distinct paths currently used by the flows (ECMP spread).",
            decimals=0,
            w=3,
        ),
        stat(
            "Path changes",
            21,
            f"round(sum(increase(etr_flow_path_changes_total{{{F}}}[$__range]))) or vector(0)",
            "none",
            "Times a flow moved to a different path in the selected time range.",
            thresholds("green", 1, "orange"),
            0,
            w=3,
        ),
    ]

    # --- Topology ---------------------------------------------------------------
    panels.append(row("Topology", 5))
    panels.append(
        panel(
            "nodeGraph",
            "Path topology",
            0,
            6,
            24,
            17,
            [inf("/api/graph/nodes", "nodes"), inf("/api/graph/edges", "edges")],
            "All hops seen in the selected time range, laid out by TTL.\n\n"
            "**Nodes**: average RTT and reply loss. Ring: green = replies, red = lost, grey = never replies, "
            "dark = only on paths no longer in use. "
            "Red outline = forwarding loss (loss that persists to later hops).\n\n"
            "**Edges**: label is the RTT added by the hop, width is the number of flows, "
            "color is forwarding loss at the target (green < 1% < orange < 5% < red). "
            "Dashed grey edges belong to paths no longer in use.\n\n"
            "Loss at a hop that does not carry on to the hops behind it is usually ICMP rate limiting, not real loss.",
            # The node graph panel ignores field overrides, but it does read config.displayName, which the
            # organize transformation sets when renaming.
            fieldConfig={"defaults": {}, "overrides": []},
            transformations=[
                {
                    "id": "organize",
                    "options": {
                        "renameByName": {
                            "mainstat": "RTT",
                            "secondarystat": "Loss / flows",
                            "arc__ok": "replies",
                            "arc__loss": "lost",
                            "arc__silent": "no reply",
                            "arc__idle": "not in use",
                            "detail__ip": "IP",
                            "detail__ptr": "PTR",
                            "detail__asn": "ASN",
                            "detail__ttl": "TTL",
                            "detail__avg": "Avg RTT",
                            "detail__p95": "p95 RTT",
                            "detail__jitter": "Jitter",
                            "detail__loss": "Reply loss",
                            "detail__fwd_loss": "Forwarding loss",
                            "detail__sent": "Probes",
                            "detail__flows": "Flows",
                            "detail__paths": "Paths",
                            "detail__in_use": "In use",
                            "detail__last_seen": "Last seen",
                        }
                    },
                }
            ],
            options={
                "nodes": {
                    "arcs": [
                        {"field": "arc__ok", "color": "green"},
                        {"field": "arc__loss", "color": "red"},
                        {"field": "arc__silent", "color": "#8e8e8e"},
                        {"field": "arc__idle", "color": "#3d3d3d"},
                    ]
                },
                "edges": {},
                "zoomMode": "cooperative",
            },
        )
    )

    # --- Path changes -----------------------------------------------------------
    panels.append(row("Path changes", 23))
    panels.append(
        panel(
            "state-timeline",
            "Path per flow",
            0,
            24,
            12,
            9,
            [prom(f"max by (protocol, src_port) (etr_flow_path_index{{{F}}})", "{{protocol}}:{{src_port}}")],
            "Which path (#N, see the Paths table) each flow used over time. A color change is a path change; "
            "gaps mean the flow was not running.",
            fieldConfig={
                "defaults": {
                    "color": {"mode": "fixed", "fixedColor": "text"},
                    "mappings": path_mappings,
                    "custom": {"fillOpacity": 80, "lineWidth": 0},
                },
                "overrides": [],
            },
            options={
                "showValue": "auto",
                "mergeValues": True,
                "alignValue": "center",
                "rowHeight": 0.85,
                "legend": {"showLegend": False, "displayMode": "list", "placement": "bottom"},
                "tooltip": {"mode": "single", "sort": "none"},
            },
        )
    )
    panels.append(
        table(
            "Path change log",
            12,
            24,
            12,
            9,
            inf(
                "/api/events",
                columns=[
                    col("time", "Time", "timestamp_epoch"),
                    col("src_port", "Flow", "number"),
                    col("change", "Change"),
                    col("ttl", "TTL", "number"),
                    col("old_hop", "From hop"),
                    col("new_hop", "To hop"),
                    col("old_route", "Old route"),
                    col("new_route", "New route"),
                ],
            ),
            "Every time a flow moved to a different path, newest first. TTL is where the old and new path diverge.",
            [
                by_name("Flow", ("custom.width", 70)),
                by_name("TTL", ("custom.width", 50)),
                by_name("Change", ("custom.width", 80)),
                by_name("Time", ("custom.width", 170)),
                long_cell("Old route"),
                long_cell("New route"),
            ],
        )
    )
    panels.append(
        table(
            "Paths",
            0,
            33,
            24,
            7,
            inf(
                "/api/paths",
                columns=[
                    col("path", "Path"),
                    col("route", "Route"),
                    col("hops", "Hops", "number"),
                    col("flows_now", "Flows now", "number"),
                    col("flows", "Flows on path"),
                    col("share_pct", "Share", "number"),
                    col("avg_ms", "Avg RTT", "number"),
                    col("p95_ms", "p95 RTT", "number"),
                    col("loss_pct", "Loss", "number"),
                    col("first_seen", "First seen", "timestamp_epoch"),
                    col("last_seen", "Last seen", "timestamp_epoch"),
                ],
            ),
            "Distinct paths seen in the time range. Numbers are assigned per target in order of discovery. "
            "RTT and loss are end-to-end for probes that took the path.",
            [
                by_name("Path", ("custom.width", 60)),
                by_name("Hops", ("custom.width", 60)),
                by_name("Flows now", ("custom.width", 90)),
                long_cell("Route", 520),
                long_cell("Flows on path"),
                by_name("Share", ("unit", "percent"), ("decimals", 0), ("custom.width", 70)),
                ms_cell("Avg RTT", "Avg RTT"),
                ms_cell("p95 RTT", "p95 RTT"),
                loss_cell("Loss"),
            ],
        )
    )

    # --- Latency & loss ---------------------------------------------------------
    panels.append(row("Latency and loss per flow", 40))
    annotated = {"fillOpacity": 0}
    panels.append(
        timeseries(
            "End-to-end RTT per flow",
            0,
            41,
            12,
            9,
            [
                prom(
                    f"sum by (src_port) (rate(etr_destination_rtt_seconds_sum{{{F}}}[$__rate_interval]))"
                    f" / sum by (src_port) (rate(etr_destination_rtt_seconds_count{{{F}}}[$__rate_interval]))",
                    ":{{src_port}}",
                )
            ],
            "s",
            "Average RTT to the destination per flow (source port). Flows on different ECMP paths separate here; "
            "path changes are marked as annotations.",
            **annotated,
        )
    )
    panels.append(
        timeseries(
            "End-to-end loss per flow",
            12,
            41,
            12,
            9,
            [
                prom(
                    "clamp_min(100 * (1 - sum by (src_port) "
                    f"(increase(etr_destination_reached_total{{{F}}}[$__rate_interval]))"
                    f" / (sum by (src_port) (increase(etr_probe_runs_total{{{F}}}[$__rate_interval])) > 0)), 0)",
                    ":{{src_port}}",
                )
            ],
            "percent",
            "Share of probes per flow without a reply from the destination.",
            **annotated,
        )
    )
    panels.append(
        panel(
            "heatmap",
            "End-to-end RTT distribution",
            0,
            50,
            12,
            8,
            [
                prom(
                    f"sum by (le) (increase(etr_destination_rtt_seconds_bucket{{{F}}}[$__rate_interval]))",
                    "{{le}}",
                    format="heatmap",
                )
            ],
            "Histogram of destination RTT over time. Bimodal bands usually mean flows on paths with different latency.",
            fieldConfig={"defaults": {"custom": {"scaleDistribution": {"type": "linear"}}}, "overrides": []},
            options={
                "calculate": False,
                "yAxis": {"unit": "s", "axisPlacement": "left"},
                "rowsFrame": {"layout": "auto"},
                "color": {
                    "mode": "scheme",
                    "scheme": "Oranges",
                    "steps": 64,
                    "exponent": 0.5,
                    "fill": "dark-orange",
                    "scale": "exponential",
                },
                "cellGap": 1,
                "filterValues": {"le": 1e-9},
                "showValue": "never",
                "tooltip": {"mode": "single", "yHistogram": False, "showColorScale": False},
                "legend": {"show": True},
                "exemplars": {"color": "rgba(255,0,255,0.7)"},
            },
        )
    )
    panels.append(
        timeseries(
            "Jitter per flow",
            12,
            50,
            12,
            8,
            [prom(f"max by (src_port) (etr_destination_jitter_seconds{{{F}}})", ":{{src_port}}")],
            "s",
            "Smoothed variation between consecutive end-to-end RTT samples (RFC 3550 style).",
        )
    )

    # --- Hops -------------------------------------------------------------------
    panels.append(row("Hops", 58))
    panels.append(
        timeseries(
            "RTT by hop",
            0,
            59,
            12,
            10,
            [
                prom(
                    f"sum by (ttl, hop_ip) (rate(etr_hop_rtt_seconds_sum{{{FH}}}[$__rate_interval]))"
                    f" / sum by (ttl, hop_ip) (rate(etr_hop_rtt_seconds_count{{{FH}}}[$__rate_interval]))",
                    "TTL {{ttl}} {{hop_ip}}",
                )
            ],
            "s",
            "Average RTT to each hop. Hop RTT includes the router's own ICMP generation time, which can be "
            "much slower than forwarding.",
        )
    )
    panels.append(
        timeseries(
            "Reply loss by hop",
            12,
            59,
            12,
            10,
            [
                prom(
                    "clamp_min(100 * (1 - sum by (ttl, hop_ip) "
                    f"(increase(etr_hop_received_total{{{FH}}}[$__rate_interval]))"
                    f" / (sum by (ttl, hop_ip) (increase(etr_hop_sent_total{{{FH}}}[$__rate_interval])) > 0)), 0)",
                    "TTL {{ttl}} {{hop_ip}}",
                )
            ],
            "percent",
            "Share of probes each hop did not answer. Loss that only shows up at one hop (and not the "
            "hops behind it) is ICMP rate limiting; compare with the Forwarding loss column below.",
        )
    )
    panels.append(
        table(
            "Hop report",
            0,
            69,
            24,
            10,
            inf(
                "/api/hops",
                columns=[
                    col("ttl", "TTL", "number"),
                    col("ip", "Hop"),
                    col("ptr", "PTR"),
                    col("asn", "ASN"),
                    col("loss_pct", "Reply loss", "number"),
                    col("fwd_loss_pct", "Fwd loss", "number"),
                    col("sent", "Sent", "number"),
                    col("avg_ms", "Avg", "number"),
                    col("best_ms", "Best", "number"),
                    col("worst_ms", "Worst", "number"),
                    col("p95_ms", "p95", "number"),
                    col("jitter_ms", "Jitter", "number"),
                    col("flows", "Flows", "number"),
                    col("paths", "Paths"),
                    col("in_use", "In use", "boolean"),
                ],
            ),
            "MTR-style report for the selected time range. Reply loss = hop did not answer. "
            "Fwd loss = lowest loss at this or any later hop for the flows crossing it: an estimate of loss "
            "that is actually forwarded, with ICMP rate limiting filtered out.",
            [
                by_name("TTL", ("custom.width", 50)),
                loss_cell("Reply loss"),
                loss_cell("Fwd loss"),
                ms_cell("Avg", "Avg"),
                ms_cell("Best", "Best"),
                ms_cell("Worst", "Worst"),
                ms_cell("p95", "p95"),
                ms_cell("Jitter", "Jitter"),
                by_name("Flows", ("custom.width", 60)),
                by_name("In use", ("custom.width", 70)),
            ],
        )
    )
    panels.append(
        table(
            "Flows",
            0,
            79,
            24,
            8,
            inf(
                "/api/flows",
                columns=[
                    col("protocol", "Proto"),
                    col("src_port", "Src port", "number"),
                    col("dst_port", "Dst port", "number"),
                    col("path", "Path"),
                    col("route", "Route"),
                    col("hops", "Hops", "number"),
                    col("loss_pct", "Loss", "number"),
                    col("avg_ms", "Avg", "number"),
                    col("p95_ms", "p95", "number"),
                    col("jitter_ms", "Jitter", "number"),
                    col("last_ms", "Last", "number"),
                    col("path_changes", "Changes", "number"),
                    col("active", "Active", "boolean"),
                ],
            ),
            "One row per flow (5-tuple). Use the source port with e.g. `iperf3 --cport` to put test traffic on the "
            "same ECMP path.",
            [
                loss_cell("Loss"),
                ms_cell("Avg", "Avg"),
                ms_cell("p95", "p95"),
                ms_cell("Jitter", "Jitter"),
                ms_cell("Last", "Last"),
                by_name("Path", ("custom.width", 60)),
                by_name("Proto", ("custom.width", 60)),
                long_cell("Route", 520),
            ],
        )
    )
    return panels


STATUS_MAPPINGS = [
    {
        "type": "value",
        "options": {
            "ok": {"text": "OK", "color": "green", "index": 0},
            "degraded": {"text": "Degraded", "color": "orange", "index": 1},
            "down": {"text": "Down", "color": "red", "index": 2},
            "stopped": {"text": "Stopped", "color": "#6e6e6e", "index": 3},
        },
    }
]

# Links from overview rows/series to the deep dive for that target.
TABLE_LINK = [
    {
        "title": "Open target",
        "targetBlank": False,
        "url": DEEP_DIVE + "?var-source=${__data.fields.Source}&var-destination=${__data.fields.Destination}"
        "&${__url_time_range}",
    }
]
SERIES_LINK = [
    {
        "title": "Open ${__field.labels.source} → ${__field.labels.destination}",
        "targetBlank": False,
        "url": DEEP_DIVE + "?var-source=${__field.labels.source}&var-destination=${__field.labels.destination}"
        "&${__url_time_range}",
    }
]


def loss_by_target(window):
    return (
        f"clamp_min(100 * (1 - {BY_TARGET} (increase(etr_destination_reached_total{{{FO}}}[{window}]))"
        f" / ({BY_TARGET} (increase(etr_probe_runs_total{{{FO}}}[{window}])) > 0)), 0)"
    )


def overview():
    panels = []
    y = 0
    panels += [
        stat(
            "Targets",
            0,
            f"count(count by (source, destination) (etr_flow_last_probe_timestamp_seconds{{{FO}}})) or vector(0)",
            "none",
            "Targets (source → destination) with flows that are currently probing.",
            decimals=0,
            y=y,
        ),
        stat(
            "Targets with loss",
            4,
            f"count({loss_by_target('1m')} >= 1) or vector(0)",
            "none",
            "Targets with at least 1% end-to-end loss over the last minute.",
            thresholds("green", 1, "orange"),
            0,
            y=y,
        ),
        stat(
            "Worst loss",
            8,
            f"max({loss_by_target('1m')})",
            "percent",
            "Highest end-to-end loss of any target over the last minute.",
            LOSS_T,
            1,
            y=y,
        ),
        stat(
            "Active flows",
            12,
            f"count(etr_flow_last_probe_timestamp_seconds{{{FO}}}) or vector(0)",
            "none",
            "Flows (5-tuples) that are currently probing, over all targets.",
            decimals=0,
            y=y,
        ),
        stat(
            "Paths in use",
            16,
            f"sum(etr_destination_active_paths{{{FO}}})",
            "none",
            "Distinct paths currently in use, summed over all targets.",
            decimals=0,
            y=y,
        ),
        stat(
            "Path changes",
            20,
            f"round(sum(increase(etr_flow_path_changes_total{{{FO}}}[$__range]))) or vector(0)",
            "none",
            "Times a flow moved to a different path in the selected time range, over all targets.",
            thresholds("green", 1, "orange"),
            0,
            y=y,
        ),
    ]
    y += 4

    targets = table(
        "Targets",
        0,
        y,
        24,
        8,
        inf(
            "/api/targets",
            params=OVERVIEW_PARAMS,
            columns=[
                col("status", "Status"),
                col("destination", "Destination"),
                col("name", "Name"),
                col("source", "Source"),
                col("flows", "Flows", "number"),
                col("paths_now", "Paths", "number"),
                col("path_changes", "Changes", "number"),
                col("last_change", "Last change", "timestamp_epoch"),
                col("loss_now_pct", "Loss now", "number"),
                col("rtt_now_ms", "RTT now", "number"),
                col("loss_pct", "Loss", "number"),
                col("avg_ms", "Avg RTT", "number"),
                col("p95_ms", "p95 RTT", "number"),
                col("jitter_ms", "Jitter", "number"),
            ],
        ),
        "One row per target: a destination as traced from one source. Click a row to open its topology, "
        "paths and hops.\n\n**Status** and the *now* columns cover the last minute; the other columns cover the "
        "selected time range. Degraded = at least 1% loss, down = at least 50%, stopped = no probes in the "
        "last 2 minutes.",
        [
            by_name(
                "Status",
                ("mappings", STATUS_MAPPINGS),
                ("custom.width", 100),
                ("custom.cellOptions", {"type": "color-background", "mode": "basic"}),
            ),
            by_name("Destination", ("links", TABLE_LINK), ("custom.width", 120)),
            by_name("Name", ("links", TABLE_LINK), ("custom.width", 240)),
            by_name("Source", ("custom.width", 110)),
            by_name("Last change", ("custom.width", 160)),
            by_name("Flows", ("custom.width", 70)),
            by_name("Paths", ("custom.width", 70)),
            by_name(
                "Changes",
                ("custom.width", 95),
                ("thresholds", thresholds("text", 1, "orange")),
                ("color", {"mode": "thresholds"}),
                ("custom.cellOptions", {"type": "color-text"}),
            ),
            loss_cell("Loss now"),
            ms_cell("RTT now", "RTT now"),
            loss_cell("Loss"),
            ms_cell("Avg RTT", "Avg RTT"),
            ms_cell("p95 RTT", "p95 RTT"),
            ms_cell("Jitter", "Jitter"),
        ]
        + [by_name(n, ("custom.width", 90)) for n in ("Loss now", "RTT now", "Loss", "Avg RTT", "p95 RTT", "Jitter")],
        sort=[{"displayName": "Destination", "desc": False}],
    )
    panels.append(targets)
    y += 8

    panels.append(
        panel(
            "state-timeline",
            "Loss per target",
            0,
            y,
            24,
            6,
            [prom(loss_by_target("$__rate_interval"), TARGET)],
            "End-to-end loss per target over time: green < 1% < orange < 5% < red. Gaps mean the target was not "
            "probed. Click a row to open the target.",
            fieldConfig={
                "defaults": {
                    "unit": "percent",
                    "decimals": 1,
                    "color": {"mode": "thresholds"},
                    "thresholds": LOSS_T,
                    "custom": {"fillOpacity": 80, "lineWidth": 0},
                    "links": SERIES_LINK,
                },
                "overrides": [],
            },
            options={
                "showValue": "never",
                "mergeValues": True,
                "alignValue": "left",
                "rowHeight": 0.8,
                "legend": {"showLegend": False, "displayMode": "list", "placement": "bottom"},
                "tooltip": {"mode": "single", "sort": "none"},
            },
        )
    )
    y += 6

    panels.append(
        timeseries(
            "End-to-end RTT per target",
            0,
            y,
            12,
            9,
            [
                prom(
                    f"{BY_TARGET} (rate(etr_destination_rtt_seconds_sum{{{FO}}}[$__rate_interval]))"
                    f" / {BY_TARGET} (rate(etr_destination_rtt_seconds_count{{{FO}}}[$__rate_interval]))",
                    TARGET,
                )
            ],
            "s",
            "Average RTT to the destination over all flows of the target. Click a series to open the target.",
            links=SERIES_LINK,
            fillOpacity=0,
        )
    )
    panels.append(
        timeseries(
            "End-to-end loss per target",
            12,
            y,
            12,
            9,
            [prom(loss_by_target("$__rate_interval"), TARGET)],
            "percent",
            "Share of probes without a reply from the destination, over all flows of the target.",
            links=SERIES_LINK,
            fillOpacity=0,
        )
    )
    y += 9
    panels.append(
        timeseries(
            "Path changes per target",
            0,
            y,
            12,
            8,
            [
                prom(
                    f"round({BY_TARGET} (increase(etr_flow_path_changes_total{{{FO}}}[$__interval])))",
                    TARGET,
                    interval="30s",
                )
            ],
            "none",
            "Flows that moved to a different path. Changes on several targets at the same time usually "
            "point to a shared hop; open the targets to compare their change logs.",
            links=SERIES_LINK,
            legend_calcs=["sum"],
            drawStyle="bars",
            fillOpacity=80,
            lineWidth=0,
            stacking={"mode": "normal", "group": "A"},
        )
    )
    panels.append(
        timeseries(
            "Paths in use per target",
            12,
            y,
            12,
            8,
            [prom(f"max by (source, destination) (etr_destination_active_paths{{{FO}}})", TARGET)],
            "none",
            "Distinct paths the flows of each target currently use. A drop usually means a link or "
            "router on one of the ECMP branches went away.",
            links=SERIES_LINK,
            legend_calcs=["min", "max", "lastNotNull"],
            lineInterpolation="stepAfter",
            fillOpacity=0,
        )
    )
    return panels


# Fleet: every site, built only from the low-cardinality etr_target_* and
# etr_hop_transit_* metrics so it also works on a central TSDB.
FF = 'source_site=~"$source_site", target_class=~"$class"'
FT = 'source_site=~"$source_site"'
PAIR = "source_site, target_site"
TGT = "source, source_site, destination, target_site, target_class"
FLEET = "/d/etr-fleet"


def ratio_loss(by, reached, probes, sel, window):
    return (
        f"clamp_min(100 * (1 - sum by ({by}) (increase({reached}{{{sel}}}[{window}]))"
        f" / (sum by ({by}) (increase({probes}{{{sel}}}[{window}])) > 0)), 0)"
    )


def target_loss(by, window="$window"):
    return ratio_loss(by, "etr_target_reached_total", "etr_target_probes_total", FF, window)


def transit_loss(window="$window"):
    return ratio_loss("hop_ip", "etr_hop_transit_reached_total", "etr_hop_transit_probes_total", FT, window)


def target_rtt(by, window="$window"):
    return (
        f"sum by ({by}) (rate(etr_target_rtt_seconds_sum{{{FF}}}[{window}]))"
        f" / sum by ({by}) (rate(etr_target_rtt_seconds_count{{{FF}}}[{window}]))"
    )


def instant(expr, ref="A"):
    return prom(expr, ref=ref, instant=True, range=False, format="table")


def matrix(title, x, y, w, h, expr, desc, defaults):
    return panel(
        "table",
        title,
        x,
        y,
        w,
        h,
        [instant(expr)],
        desc,
        transformations=[
            {
                "id": "groupingToMatrix",
                "options": {
                    "columnField": "target_site",
                    "rowField": "source_site",
                    "valueField": "Value",
                    "emptyValue": "null",
                },
            }
        ],
        fieldConfig={
            "defaults": {
                **defaults,
                "custom": {
                    "align": "center",
                    "minWidth": 56,
                    "cellOptions": {"type": "color-background", "mode": "basic"},
                },
                "mappings": [
                    {"type": "special", "options": {"match": "null", "result": {"text": "", "color": "transparent"}}}
                ],
            },
            "overrides": [
                by_name(
                    "source_site\\target_site",
                    ("displayName", "From ↓  To →"),
                    ("custom.cellOptions", {"type": "auto"}),
                    ("custom.align", "left"),
                    ("custom.width", 100),
                )
            ],
        },
        options={"showHeader": True, "cellHeight": "sm", "footer": {"show": False, "reducer": ["sum"], "fields": ""}},
    )


def merged_table(title, x, y, w, h, targets, desc, rename, overrides, sort):
    names = {"Time": 0, **{k: i + 1 for i, k in enumerate(rename)}}
    return panel(
        "table",
        title,
        x,
        y,
        w,
        h,
        targets,
        desc,
        transformations=[
            {"id": "merge", "options": {}},
            {
                "id": "organize",
                "options": {"excludeByName": {"Time": True}, "indexByName": names, "renameByName": rename},
            },
        ],
        fieldConfig={
            "defaults": {"custom": {"align": "auto", "filterable": True, "cellOptions": {"type": "auto"}}},
            "overrides": overrides,
        },
        options={
            "showHeader": True,
            "cellHeight": "sm",
            "footer": {"show": False, "reducer": ["sum"], "fields": ""},
            "sortBy": sort,
        },
    )


FLEET_TABLE_LINK = [
    {
        "title": "Open ${__data.fields.source} → ${__data.fields.destination}",
        "targetBlank": False,
        "url": DEEP_DIVE + "?var-source=${__data.fields.source}&var-destination=${__data.fields.destination}"
        "&${__url_time_range}",
    }
]
PAIR_LEGEND = "{{source_site}} → {{target_site}}"


def fleet():
    panels = []
    y = 0
    panels += [
        stat(
            "Sites",
            0,
            f"count(count by (source_site) (etr_target_paths{{{FF}}} > 0)) or vector(0)",
            "none",
            "Sites with at least one target that is currently probing.",
            decimals=0,
            y=y,
        ),
        stat(
            "Targets",
            4,
            f"count(etr_target_paths{{{FF}}} > 0) or vector(0)",
            "none",
            "Targets (source → destination) that are currently probing.",
            decimals=0,
            y=y,
        ),
        stat(
            "Targets with loss",
            8,
            f"count({target_loss(TGT)} >= 1) or vector(0)",
            "none",
            "Targets with at least 1% end-to-end loss over the window.",
            thresholds("green", 1, "orange"),
            0,
            y=y,
        ),
        stat(
            "Worst loss",
            12,
            f"max({target_loss(TGT)})",
            "percent",
            "Highest end-to-end loss of any target over the window.",
            LOSS_T,
            1,
            y=y,
        ),
        stat(
            "Paths in use",
            16,
            f"sum(etr_target_paths{{{FF}}})",
            "none",
            "Distinct paths currently in use, summed over all targets.",
            decimals=0,
            y=y,
        ),
        stat(
            "Path changes",
            20,
            f"round(sum(increase(etr_target_path_changes_total{{{FF}}}[$window]))) or vector(0)",
            "none",
            "Times a flow moved to a different path within the window, over all targets.",
            thresholds("green", 1, "orange"),
            0,
            y=y,
        ),
    ]
    y += 4

    panels.append(row("Site × site (last $window)", y))
    y += 1
    panels.append(
        matrix(
            "Loss",
            0,
            y,
            12,
            10,
            target_loss(PAIR),
            "End-to-end loss from each source site (rows) to each target site (columns) over the window, all "
            "targets and flows of the pair combined. A bad row points at the source site, a bad column at the "
            "target site, a block of cells at a link between regions.",
            {"unit": "percent", "decimals": 1, "thresholds": LOSS_T, "color": {"mode": "thresholds"}, "noValue": "–"},
        )
    )
    panels.append(
        matrix(
            "Average RTT",
            12,
            y,
            12,
            10,
            target_rtt(PAIR),
            "Average end-to-end round-trip time from each source site (rows) to each target site (columns) over "
            "the window.",
            {
                "unit": "s",
                "decimals": 1,
                "color": {"mode": "continuous-BlPu"},
                "noValue": "–",
                "thresholds": thresholds("blue"),
            },
        )
    )
    y += 10

    panels.append(row("Where to look", y))
    y += 1
    top = f"topk(20, {target_loss(TGT)})"
    only_top = f" and on (source, destination) {top}"
    panels.append(
        merged_table(
            "Worst targets",
            0,
            y,
            14,
            11,
            [
                instant(top, "A"),
                instant(target_rtt(TGT) + only_top, "B"),
                instant(
                    f"round(sum by ({TGT}) (increase(etr_target_path_changes_total{{{FF}}}[$window])))" + only_top, "C"
                ),
                instant(f"max by ({TGT}) (etr_target_paths{{{FF}}})" + only_top, "D"),
            ],
            "The 20 targets with the highest end-to-end loss over the window. Click a row to open the target's "
            "topology, paths and hops (served by the exporter of the source site).",
            {
                "source_site": "From",
                "target_site": "To",
                "source": "source",
                "destination": "destination",
                "target_class": "Class",
                "Value #A": "Loss",
                "Value #B": "Avg RTT",
                "Value #C": "Changes",
                "Value #D": "Paths",
            },
            [
                loss_cell("Loss"),
                by_name("Avg RTT", ("unit", "s"), ("decimals", 1)),
                by_name(
                    "Changes",
                    ("thresholds", thresholds("text", 1, "orange")),
                    ("color", {"mode": "thresholds"}),
                    ("custom.cellOptions", {"type": "color-text"}),
                ),
                by_name("source", ("displayName", "Source"), ("links", FLEET_TABLE_LINK)),
                by_name("destination", ("displayName", "Destination"), ("links", FLEET_TABLE_LINK)),
            ]
            + [
                by_name(n, ("custom.width", w))
                for n, w in (
                    ("From", 65),
                    ("To", 80),
                    ("Class", 70),
                    ("Loss", 75),
                    ("Avg RTT", 90),
                    ("Changes", 90),
                    ("Paths", 70),
                )
            ],
            [{"displayName": "Loss", "desc": True}],
        )
    )

    crossing = f"sum by (hop_ip) (etr_hop_transit_targets{{{FT}}})"
    shared = f"({transit_loss()} and on (hop_ip) ({crossing} >= 2))"
    ptr = " * on (hop_ip) group_left (hop_ptr) max by (hop_ip, hop_ptr) (etr_hop_info)"
    top_hops = f"topk(15, {shared}{ptr})"
    panels.append(
        merged_table(
            "Shared hops",
            14,
            y,
            10,
            11,
            [
                instant(top_hops, "A"),
                instant(f"{crossing}{ptr} and on (hop_ip) {top_hops}", "B"),
                instant(f"count by (hop_ip) (etr_hop_transit_targets{{{FT}}}){ptr} and on (hop_ip) {top_hops}", "C"),
            ],
            "Routers crossed by two or more targets, ranked by the end-to-end loss of the traffic that goes "
            "through them, over all selected sites. When several targets fail through the same hop, that hop (or "
            "the link in front of it) is the likely cause. Not filtered by class.",
            {"hop_ip": "Hop", "hop_ptr": "Name", "Value #A": "Loss", "Value #B": "Targets", "Value #C": "Sites"},
            [
                loss_cell("Loss"),
                by_name("Hop", ("custom.width", 105)),
                by_name("Targets", ("custom.width", 80)),
                by_name("Sites", ("custom.width", 65)),
                by_name("Loss", ("custom.width", 75)),
            ],
            [{"displayName": "Loss", "desc": True}],
        )
    )
    y += 11

    panels.append(row("Trends", y))
    y += 1
    panels.append(
        timeseries(
            "Loss by site pair",
            0,
            y,
            12,
            8,
            [prom(target_loss(PAIR), PAIR_LEGEND)],
            "percent",
            "End-to-end loss per source site → target site over time, over a sliding window (the "
            "*Window* variable) because a few flows every few seconds give noisy short-term loss.",
            fillOpacity=0,
        )
    )
    panels.append(
        timeseries(
            "RTT by site pair",
            12,
            y,
            12,
            8,
            [prom(target_rtt(PAIR, "$__rate_interval"), PAIR_LEGEND)],
            "s",
            "Average end-to-end RTT per source site → target site. Steps usually mean a reroute.",
            fillOpacity=0,
        )
    )
    y += 8
    panels.append(
        timeseries(
            "Path changes by site pair",
            0,
            y,
            12,
            8,
            [
                prom(
                    f"round(sum by ({PAIR}) (increase(etr_target_path_changes_total{{{FF}}}[$__interval]))) > 0",
                    PAIR_LEGEND,
                    interval="30s",
                )
            ],
            "none",
            "Flows that moved to a different path. Many pairs changing at once means a shared link or router changed.",
            legend_calcs=["sum"],
            drawStyle="bars",
            fillOpacity=80,
            lineWidth=0,
            stacking={"mode": "normal", "group": "A"},
        )
    )
    panels.append(
        timeseries(
            "Loss through shared hops",
            12,
            y,
            12,
            8,
            [prom(f"{shared}{ptr} > 0", "{{hop_ptr}} ({{hop_ip}})")],
            "percent",
            "End-to-end loss of the traffic crossing each shared hop, over a sliding window (the "
            "*Window* variable). Only hops with loss are shown.",
            fillOpacity=0,
        )
    )
    return panels


def var(name, label, query, multi=True):
    v = {
        "name": name,
        "label": label,
        "type": "query",
        "datasource": PROM,
        "definition": query,
        "query": {"query": query, "refId": "PrometheusVariableQueryEditor-VariableQuery"},
        "refresh": 2,
        "includeAll": multi,
        "multi": multi,
        "sort": 3,
        "regex": "",
        "options": [],
    }
    if multi:
        v["current"] = {"selected": True, "text": ["All"], "value": ["$__all"]}
    return v


def interval_var(name, label, options, default):
    return {
        "name": name,
        "label": label,
        "type": "custom",
        "query": ",".join(options),
        "current": {"selected": True, "text": default, "value": default},
        "options": [{"selected": o == default, "text": o, "value": o} for o in options],
    }


ANNOTATIONS_BUILTIN = {
    "builtIn": 1,
    "datasource": {"type": "grafana", "uid": "-- Grafana --"},
    "enable": True,
    "hide": True,
    "iconColor": "rgba(0, 211, 255, 1)",
    "name": "Annotations & Alerts",
    "type": "dashboard",
}


def dashboard(uid, title, desc, panels, variables, annotations, links):
    return {
        "uid": uid,
        "title": title,
        "description": desc,
        "tags": ["etr", "network", "traceroute", "ecmp"],
        "timezone": "browser",
        "editable": True,
        "graphTooltip": 1,
        "refresh": "10s",
        "time": {"from": "now-15m", "to": "now"},
        "schemaVersion": 39,
        "version": 1,
        "links": links,
        "templating": {"list": variables},
        "annotations": {"list": [ANNOTATIONS_BUILTIN] + annotations},
        "panels": panels,
    }


def link(title, url, icon):
    return {
        "title": title,
        "type": "link",
        "url": url,
        "icon": icon,
        "keepTime": True,
        "includeVars": False,
        "asDropdown": False,
        "tags": [],
        "targetBlank": False,
        "tooltip": "",
    }


dashboards = {
    "etr-overview.json": dashboard(
        "etr-overview",
        "ETR · Overview",
        "Every etr target (source → destination) at a glance.",
        overview(),
        [var("source", "Source", "label_values(etr_probe_runs_total, source)")],
        [
            {
                "datasource": PROM,
                "enable": True,
                "iconColor": "orange",
                "name": "Path changes",
                "expr": f"{BY_TARGET} (changes(etr_flow_path_index{{{FO}}}[30s])) > 0",
                "step": "30s",
                "titleFormat": "Path change",
                "textFormat": TARGET,
                "tagKeys": "source,destination",
                "useValueForTime": False,
            }
        ],
        [link("Fleet", FLEET, "apps"), link("Target details", DEEP_DIVE, "dashboard")],
    ),
    "etr-dashboard.json": dashboard(
        "etr-paths",
        "ETR · Target details",
        "Path topology, path changes, latency and loss for one etr target (source → destination).",
        deep_dive(),
        [
            var("destination", "Destination", "label_values(etr_probe_runs_total, destination)", multi=False),
            var(
                "source",
                "Source",
                'label_values(etr_probe_runs_total{destination="$destination"}, source)',
                multi=False,
            ),
            var(
                "src_port",
                "Flow (source port)",
                'label_values(etr_probe_runs_total{source="$source", destination="$destination"}, src_port)',
            ),
        ],
        [
            {
                "datasource": PROM,
                "enable": True,
                "iconColor": "orange",
                "name": "Path changes",
                "expr": f"sum by (src_port) (changes(etr_flow_path_index{{{F}}}[30s])) > 0",
                "step": "30s",
                "titleFormat": "Path change",
                "textFormat": "flow :{{src_port}}",
                "tagKeys": "src_port",
                "useValueForTime": False,
            }
        ],
        [link("Overview", OVERVIEW, "arrow-left"), link("Fleet", FLEET, "apps")],
    ),
    "etr-fleet.json": dashboard(
        "etr-fleet",
        "ETR · Fleet",
        "Every site at a glance: site × site loss and RTT, worst targets and shared hops. Uses only the "
        "low-cardinality etr_target_* and etr_hop_transit_* metrics, so it also works on a central TSDB.",
        fleet(),
        [
            var("source_site", "From site", "label_values(etr_target_probes_total, source_site)"),
            var("class", "Target class", "label_values(etr_target_probes_total, target_class)"),
            interval_var("window", "Window", ["1m", "5m", "15m", "1h"], "5m"),
        ],
        [],
        [link("Overview", OVERVIEW, "arrow-left"), link("Target details", DEEP_DIVE, "dashboard")],
    ),
}


def main():
    out_dir = (
        sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboards")
    )
    for name, d in dashboards.items():
        with open(os.path.join(out_dir, name), "w") as f:
            f.write(json.dumps(d, indent=2) + "\n")
        print(f"wrote {name}: {len(d['panels'])} panels")


if __name__ == "__main__":
    main()
