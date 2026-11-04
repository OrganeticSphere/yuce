"""Owner-facing provenance and current associations; never a semantic grade."""
def enrich(snapshot, models):
    models=dict(models)
    models["kernel"]={"model":None,"nature":"deterministic_kernel"}
    models["base"]={"model":None,"nature":"genesis_seed"}
    snapshot["model_attribution"]="Configured agent model/nature; exact per-call effort remains in the call journal."
    snapshot["models"]=models
    events=snapshot.get("events") or []
    mappings=snapshot.get("current_mappings")
    for e in events:
        e["agent_model"]=models.get(e.get("subject"),{}).copy()
        for key in ("proposer","initial_reviewer"):
            if key in e:e[key+"_model"]=models.get(e[key],{}).copy()
    seeds=set(snapshot.get("seed_ids") or [])
    for c in (snapshot.get("ontology") or {}).get("concepts") or []:
        cid=c["id"]
        own=[e for e in events if e.get("concept")==cid or (e.get("change") or {}).get("concept")==cid
             or any(v.get("id")==cid for v in (e.get("result") or {}).get("into") or [])]
        confirmed=[e for e in own if e.get("status")=="confirmed"]
        moved=[m for e in events if e.get("status")=="confirmed" for m in (e.get("result") or {}).get("moves") or []]
        c["evolution"]={"initial":cid in seeds,"proposed_by":c.get("proposed_by"),"proposer_model":models.get(c.get("proposed_by"),{}).copy(),
            "revisions":own,"confirmers":[{"subject":e.get("subject"),"agent_model":e.get("agent_model"),"proposal":e.get("proposal")} for e in confirmed],
            "mappings_moved_out":sum(m.get("from")==cid for m in moved),"mappings_moved_in":sum(m.get("to")==cid for m in moved),
            "mapping_count":sum(m.get("concept")==cid for m in mappings) if mappings is not None else None,
            "mappings_on_narrowed_concept":sum(m.get("concept")==cid for m in mappings) if mappings is not None and c.get("status")=="narrowed" else 0,
            "unattested_reason":c.get("attestation_reason") if c.get("status")=="unattested" else None,
            "attestation_history":[e for e in own if e.get("op")=="ontology_attestation"]}
    # Historical retrieval hints are retained only here; never feed zero mappings back as a model task.
    snapshot["unmapped_seed_summary"]=[{"concept":c["id"],"status":c.get("status"),"mapping_count":0,"interpretation":"inventory only; not proof of absence"}
        for c in (snapshot.get("ontology") or {}).get("concepts") or [] if c["id"] in seeds and mappings is not None and not any(m.get("concept")==c["id"] for m in mappings)]
    return snapshot
