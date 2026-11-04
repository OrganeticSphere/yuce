"""Per-work effort ladder. Models retain their provider/family; settings are opt-in."""
from __future__ import annotations
import json

LEVELS = ("low", "medium", "high")
PHASES = ("READ", "BUILD", "VERIFY", "ANSWER")

def parse_phase_effort(spec):
    if spec is None:
        return None
    out={}
    for item in spec.split(","):
        parts=item.split("=")
        if len(parts)!=2 or parts[0] not in PHASES or parts[1] not in LEVELS or parts[0] in out:
            raise ValueError("phase effort needs distinct READ/BUILD/VERIFY/ANSWER=low|medium|high")
        out[parts[0]]=parts[1]
    if set(out)!=set(PHASES):
        raise ValueError("phase effort must specify READ, BUILD, VERIFY and ANSWER")
    return out

def phase_of(role):
    if role in ("BUILD", "BUILDER"):
        return "BUILD"
    if role == "REFINER":
        return "REFINE"
    if role in ("VERIFY_LINK", "RESOLVE_CONFLICT"):
        return "VERIFY"
    if role in ("SUMMARIZE", "LEAD", "UPDATE", "ANSWER", "RESTATE", "SINGLE", "WHOLE"):
        return "ANSWER"
    if role == "JEV":
        return None
    return "READ"

class EffortPolicy:
    def __init__(self, configured=None, anomaly_effort=None, failure_ladder=False):
        self.configured=dict(configured or {})
        self.levels={}
        self.causes={}
        self.failure_ladder=failure_ladder
        self.anomaly_effort=anomaly_effort
        self.anomaly_keys=set()

    def key(self, arm, role, phase, context):
        category=phase_of(role)
        identity=context.get("card_id") or context.get("key") or context.get("rq_id") or context.get("task_id")
        if identity is None:
            identity=json.dumps([context.get("report"),context.get("section"),role],sort_keys=True)
        return (arm,phase,category,str(identity))

    def select(self, model, arm, role, phase, context, answer_timeout_s):
        category=phase_of(role)
        key=self.key(arm,role,phase,context)
        base=self.configured.get(category)
        anomaly=category=="BUILD" and self.anomaly_effort is not None and context.get("ontology_anomaly")
        if anomaly:
            base=self.anomaly_effort
            self.anomaly_keys.add(key)
        if base is None and (category=="ANSWER" or self.failure_ladder) and hasattr(model,"for_role"):
            suffix=getattr(model,"name","").rsplit("-",1)[-1]
            base=suffix if suffix in LEVELS else None
        fresh=key not in self.levels
        level=self.levels.setdefault(key,base)
        if fresh and anomaly:self.causes[key]="ontology_anomaly"
        timeout=answer_timeout_s if category=="ANSWER" else None
        chosen=model
        if hasattr(model,"for_role") and (level is not None or timeout is not None):
            chosen=model.for_role(level,timeout_s=timeout)
        applied=level is not None and hasattr(model,"for_role")
        return chosen, {"effort":level if applied else None, "effort_requested":level,
                        "model_family":getattr(chosen,"model_family",getattr(model,"name","unknown")),
                        "effort_reason":self.causes.get(key,"phase_default") if level else None}

    def change(self, arm, role, phase, context, cause):
        category=phase_of(role)
        key=self.key(arm,role,phase,context)
        if category not in self.configured and category!="ANSWER" and key not in self.anomaly_keys and not self.failure_ladder:return None
        old=self.levels.get(key,self.configured.get(category))
        if old is None:
            new="medium" if cause=="kernel_repair" else "low"
            self.levels[key]=new;self.causes[key]=cause
            return {"arm":arm,"phase":phase,"work":key[3],"effort_phase":category,"previous":old,"effort":new,"cause":cause}
        index=LEVELS.index(old)
        new=("high" if key in self.anomaly_keys else LEVELS[min(2,index+1)]) if cause=="kernel_repair" else LEVELS[max(0,index-1)]
        self.levels[key]=new
        self.causes[key]=cause
        return {"arm":arm,"phase":phase,"work":key[3],"effort_phase":category,"previous":old,"effort":new,"cause":cause}
