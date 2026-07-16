from pydantic import BaseModel
from typing import List, Dict, Any

class GraphNodeData(BaseModel):
    id: str
    label: str
    type: str
    is_admin: bool
    risk_score: float
    dangerous_actions: List[str]

class GraphNode(BaseModel):
    data: GraphNodeData

class GraphEdgeData(BaseModel):
    id: str
    source: str
    target: str
    label: str
    type: str
    description: str

class GraphEdge(BaseModel):
    data: GraphEdgeData

class CytoscapeGraphResponse(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]
