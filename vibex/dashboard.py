# dashboard.py — Real-time Network IDS Dashboard

import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output
import plotly.graph_objs as go
from collections import deque
from datetime import datetime
import threading

MAX_PACKETS = 500

store = {
    "packets":   deque(maxlen=MAX_PACKETS),
    "malicious": deque(maxlen=MAX_PACKETS),
    "timeline":  deque(maxlen=60),
    "total":     0,
    "mal_count": 0,
    "lock":      threading.Lock(),
}


def record_packet(pkt_summary, src_ip, dst_ip, protocol,
                  if_result, ae_result, lstm_result, votes, verdict):
    now = datetime.now()
    row = {
        "time":     now.strftime("%H:%M:%S"),
        "src_ip":   src_ip,
        "dst_ip":   dst_ip,
        "protocol": protocol,
        "if":       if_result,
        "ae":       ae_result,
        "lstm":     lstm_result,
        "votes":    f"{votes}/3",
        "verdict":  verdict,
        "summary":  pkt_summary[:60],
    }
    with store["lock"]:
        store["packets"].appendleft(row)
        store["total"] += 1
        if verdict == "MALICIOUS":
            store["mal_count"] += 1
            store["malicious"].appendleft(row)
        ts = now.strftime("%H:%M:%S")
        if store["timeline"] and store["timeline"][-1]["ts"] == ts:
            store["timeline"][-1]["total"] += 1
            if verdict == "MALICIOUS":
                store["timeline"][-1]["mal"] += 1
            else:
                store["timeline"][-1]["ben"] += 1
        else:
            store["timeline"].append({
                "ts":    ts,
                "total": 1,
                "mal":   1 if verdict == "MALICIOUS" else 0,
                "ben":   0 if verdict == "MALICIOUS" else 1,
            })


# ── Helpers defined FIRST before layout ─────────────────────────

def _stat_card(card_id, label, color):
    return html.Div([
        html.Div(label, style={"fontSize": "12px", "color": "#888", "marginBottom": "6px"}),
        html.Div(id=card_id, children="0",
                 style={"fontSize": "24px", "fontWeight": "500", "color": color}),
    ], style={"background": "#f4f4f4", "borderRadius": "8px", "padding": "14px 16px"})


def _card_style():
    return {
        "background": "white",
        "border": "1px solid #e5e5e5",
        "borderRadius": "10px",
        "padding": "16px",
    }


# ── App ──────────────────────────────────────────────────────────

app = dash.Dash(__name__, suppress_callback_exceptions=True)
app.title = "Network IDS Dashboard"

app.layout = html.Div([

    dcc.Interval(id="ids-interval", interval=2000, n_intervals=0),

    # Header
    html.Div([
        html.H2("Network IDS — Live Dashboard",
                style={"margin": "0", "fontWeight": "500", "fontSize": "20px"}),
        html.Span("● LIVE", style={"color": "#3B6D11", "fontSize": "13px", "marginLeft": "12px"}),
    ], style={"display": "flex", "alignItems": "center", "padding": "16px 24px",
              "borderBottom": "1px solid #e5e5e5", "marginBottom": "20px"}),

    # Stat cards
    html.Div([
        _stat_card("ids-total",  "Total Packets", "#333"),
        _stat_card("ids-benign", "Benign",        "#3B6D11"),
        _stat_card("ids-mal",    "Malicious",     "#A32D2D"),
        _stat_card("ids-pct",    "Malicious %",   "#BA7517"),
    ], style={"display": "grid", "gridTemplateColumns": "repeat(4, 1fr)",
              "gap": "12px", "padding": "0 24px", "marginBottom": "20px"}),

    # Charts row
    html.Div([
        html.Div([
            html.Div("Packets over time",
                     style={"fontSize": "13px", "fontWeight": "500", "marginBottom": "8px"}),
            dcc.Graph(id="ids-timeline", config={"displayModeBar": False},
                      style={"height": "200px"}),
        ], style=_card_style()),

        html.Div([
            html.Div("Verdict split",
                     style={"fontSize": "13px", "fontWeight": "500", "marginBottom": "8px"}),
            dcc.Graph(id="ids-pie", config={"displayModeBar": False},
                      style={"height": "200px"}),
        ], style=_card_style()),
    ], style={"display": "grid", "gridTemplateColumns": "2fr 1fr",
              "gap": "12px", "padding": "0 24px", "marginBottom": "20px"}),

    # Malicious table
    html.Div([
        html.Div("Recent malicious packets",
                 style={"fontSize": "13px", "fontWeight": "500", "marginBottom": "10px"}),
        dash_table.DataTable(
            id="ids-table",
            columns=[
                {"name": "Time",     "id": "time"},
                {"name": "Src IP",   "id": "src_ip"},
                {"name": "Dst IP",   "id": "dst_ip"},
                {"name": "Protocol", "id": "protocol"},
                {"name": "IF",       "id": "if"},
                {"name": "AE",       "id": "ae"},
                {"name": "LSTM",     "id": "lstm"},
                {"name": "Votes",    "id": "votes"},
                {"name": "Summary",  "id": "summary"},
            ],
            data=[],
            page_size=10,
            style_table={"overflowX": "auto"},
            style_header={
                "backgroundColor": "#f9f9f9", "fontWeight": "500",
                "fontSize": "12px", "border": "none",
                "borderBottom": "1px solid #e5e5e5",
            },
            style_cell={
                "fontSize": "12px", "padding": "8px 10px",
                "border": "none", "borderBottom": "1px solid #f0f0f0",
                "fontFamily": "inherit", "textAlign": "left",
                "maxWidth": "160px", "overflow": "hidden",
                "textOverflow": "ellipsis",
            },
            style_data_conditional=[
                {"if": {"filter_query": '{votes} = "3/3"'},
                 "backgroundColor": "#FFF5F5", "color": "#A32D2D"},
            ],
        ),
    ], style={**_card_style(), "padding": "16px 24px", "margin": "0 24px 24px 24px"}),

], style={"fontFamily": "system-ui, sans-serif", "color": "#333",
          "backgroundColor": "#fafafa", "minHeight": "100vh"})


# ── Callback ─────────────────────────────────────────────────────

@app.callback(
    Output("ids-total",    "children"),
    Output("ids-benign",   "children"),
    Output("ids-mal",      "children"),
    Output("ids-pct",      "children"),
    Output("ids-timeline", "figure"),
    Output("ids-pie",      "figure"),
    Output("ids-table",    "data"),
    Input("ids-interval",  "n_intervals"),
)
def update(_):
    with store["lock"]:
        total    = store["total"]
        mal      = store["mal_count"]
        benign   = total - mal
        pct      = round(100 * mal / total, 1) if total else 0
        timeline = list(store["timeline"])
        mal_rows = list(store["malicious"])

    def num(value, color):
        return html.Span(str(value),
                         style={"fontSize": "24px", "fontWeight": "500", "color": color})

    # Timeline
    times = [t["ts"]  for t in timeline]
    bens  = [t["ben"] for t in timeline]
    mals  = [t["mal"] for t in timeline]

    tl = go.Figure()
    tl.add_trace(go.Scatter(x=times, y=bens, name="Benign",
                            line={"color": "#3B6D11", "width": 2},
                            fill="tozeroy", fillcolor="rgba(59,109,17,0.08)"))
    tl.add_trace(go.Scatter(x=times, y=mals, name="Malicious",
                            line={"color": "#A32D2D", "width": 2},
                            fill="tozeroy", fillcolor="rgba(163,45,45,0.08)"))
    tl.update_layout(
        margin={"t": 4, "b": 4, "l": 4, "r": 4},
        plot_bgcolor="white", paper_bgcolor="white",
        legend={"orientation": "h", "y": -0.2, "font": {"size": 11}},
        xaxis={"showgrid": False, "tickfont": {"size": 10}},
        yaxis={"showgrid": True, "gridcolor": "#f0f0f0", "tickfont": {"size": 10}},
        hovermode="x unified",
    )

    # Pie
    pie = go.Figure(go.Pie(
        labels=["Benign", "Malicious"],
        values=[max(benign, 0), max(mal, 0)],
        marker_colors=["#3B6D11", "#A32D2D"],
        hole=0.55, textfont={"size": 11},
    ))
    pie.update_layout(
        margin={"t": 4, "b": 4, "l": 4, "r": 4},
        paper_bgcolor="white",
        legend={"font": {"size": 11}, "orientation": "h", "y": -0.1},
    )

    return (
        num(total,      "#333"),
        num(benign,     "#3B6D11"),
        num(mal,        "#A32D2D"),
        num(f"{pct}%",  "#BA7517"),
        tl, pie, mal_rows,
    )


if __name__ == "__main__":
    print("=" * 50)
    print("  IDS Dashboard → http://localhost:8050")
    print("=" * 50)
    app.run(debug=False, port=8050)
