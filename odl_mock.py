from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn, time

app = FastAPI(title="ODL Mock Controller")

_state = {
    "nodes": ["s2", "h3", "h4"],
    "flows": [],
    "sync_state": "SYNCHRONIZED",
    "load_pct": 35.0,
}

@app.get("/health")
def health():
    return {"controller": "ODL-Mock", "status": "UP", "port": 8182}

@app.get("/restconf/operational/network-topology:network-topology")
def get_topology():
    return {"network-topology": {"topology": [{"topology-id": "flow:1",
        "node": [{"node-id": n} for n in _state["nodes"]]}]}}

@app.put("/restconf/operational/network-topology:network-topology")
async def update_topology(request: Request):
    body = await request.json()
    return {"status": "TOPOLOGY_UPDATED", "timestamp": time.time()}

@app.get("/restconf/operational/opendaylight-inventory:nodes")
def get_nodes():
    return {"nodes": {"node": [{"id": "openflow:2", "state": "ACTIVE"}]}}

@app.post("/restconf/config/opendaylight-inventory:nodes/node/openflow:2/flow-node-inventory:table/0/flow/1")
async def add_flow(request: Request):
    body = await request.json()
    _state["flows"].append(body)
    return {"status": "FLOW_ADDED", "flow_id": len(_state["flows"])}

@app.post("/restconf/operational/sync")
async def sync(request: Request):
    return {"status": "SYNC_OK", "state": "SYNCHRONIZED", "timestamp": time.time()}

@app.get("/restconf/operational/sync/state")
def sync_state():
    return {"sync_state": _state["sync_state"], "load_pct": _state["load_pct"]}

@app.post("/restconf/config/policy")
async def push_policy(request: Request):
    body = await request.json()
    return {"status": "POLICY_APPLIED", "timestamp": time.time()}

@app.get("/onos/v1/topology")
def onos_compat():
    return get_topology()

if __name__ == "__main__":
    print("[ODL-MOCK] Simulateur ODL sur :8182")
    uvicorn.run(app, host="0.0.0.0", port=8182)
