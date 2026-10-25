# SPDX-License-Identifier: Apache-2.0
"""spec-0.4.1 cases (JSON lines, SPEC.md section 11 vector format): pending envelopes, job results
bound to the original request, and mesh documents.

- jobs: a pending envelope, or the result served at a job URL, around a validly signed receipt where
  there is one. What varies: whether the request was a /cell request or a poll of a job (request.job),
  the echoed request (the same, another cell, an asof added, dropped or moved), the job and poll (the
  job polled, another job, too short, uppercase, an http poll), the members (receipt or trust added to
  pending, estimate_seconds missing or fractional), and the result's binding to the original request
  (another cell, a later asof). E_JOB_UNKNOWN under bad_request and error, at a job URL and not.
- mesh: a key document and a mesh document for mesh.example.org, each correct or mutated (host,
  proto, an endpoint or the bindings URL on another host, a placeholder missing or added, a required
  endpoint dropped, unknown members added, malformed text, a failed retrieval).
The reference tool signs; the libraries only run.

    python generate_041.py SPEC_REPO N SEED > spec041.jsonl
"""

import json
import random
import sys

SPEC, N, SEED = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
sys.path[:0] = [f"{SPEC}/tools"]
import canon  # noqa: E402

rng = random.Random(SEED)
HOST = "rates.example.org"
SEED_KEY = bytes([61]) * 32
_, PUBLIC = canon.keypair(SEED_KEY)
KEY = {"alg": "ed25519", "id": canon.key_id(PUBLIC), "public": PUBLIC.hex(), "valid_from": "2020-01-01T00:00:00.000000Z"}
KEYS = {HOST: {"https": {"status": 200, "body": json.dumps({"host": HOST, "keys": [KEY], "proto": canon.PROTO})}}}
ASOF = "2024-03-16T09:00:00.000000Z"
ASOFS = [ASOF, "2024-03-16T08:59:59.999999Z", "2024-03-16T09:00:00.000001Z", "2025-01-01T00:00:00.000000Z"]


def cell(quote="USD"):
    return {"args": {"base": {"type": "string", "value": "EUR"}, "date": {"type": "date", "value": "2024-03-15"},
                     "quote": {"type": "string", "value": quote}}, "fn": "fx_rate", "fn_hash": "1" * 64, "ns": HOST}


def cell_id(c):
    return canon.sha256_hex(canon.jcs(c))


def receipt(c):
    r = {"asof": ASOF, "cell": c, "computed_by": f"{HOST}#{KEY['id']}", "inputs": [], "issued": ASOF,
         "licence": "CC-BY-4.0", "proto": canon.PROTO, "publisher": HOST, "summary": "A rate.",
         "tx": "2024-03-15T16:00:00.000000Z", "type": "number", "valid": {"date": c["args"]["date"]}, "value": "1.0892"}
    return canon.sign_receipt(r, SEED_KEY)


CELLS = [cell(), cell("GBP")]
RECEIPTS = [receipt(c) for c in CELLS]


def job_id():
    return "".join(rng.choice("0123456789abcdef") for _ in range(rng.choice([32, 32, 40, 64])))


def jobs(i):
    request = {"cell_id": cell_id(CELLS[0])}
    if rng.random() < 0.7:
        request["asof"] = rng.choice(ASOFS)
    job = job_id()
    polled = rng.random() < 0.6
    if polled:
        request["job"] = job
    kind = rng.choice(["pending", "pending", "pending", "result", "result", "unknown"])
    if kind == "pending":
        echoed = {k: v for k, v in request.items() if k != "job"}
        r = rng.random()
        if r < 0.1:
            echoed["cell_id"] = cell_id(CELLS[1])
        elif r < 0.2:
            echoed.pop("asof", None) if "asof" in echoed else echoed.update(asof=ASOF)
        elif r < 0.25 and "asof" in echoed:
            echoed["asof"] = rng.choice([a for a in ASOFS if a != echoed["asof"]])
        elif r < 0.3:
            echoed["extra"] = 1
        env_job = job
        r = rng.random()
        if r < 0.1:
            env_job = job_id()  # another job than the one polled (only matters when polled)
        elif r < 0.15:
            env_job = job[:31]
        elif r < 0.2:
            env_job = job.upper()
        poll = f"https://mesh.example/jobs/{env_job}"
        r = rng.random()
        if r < 0.05:
            poll = poll.replace("https://", "http://")
        elif r < 0.1:
            poll = f"https://mesh.example/jobs/{job_id()}"
        elif r < 0.13:
            poll = "https://mesh.example/" + "x" * 500 + f"/jobs/{env_job}"
        env = {"estimate_seconds": rng.choice([0, 1, 30, 9007199254740991]), "job": env_job, "outcome": "pending",
               "poll": poll, "request": echoed}
        r = rng.random()
        if r < 0.05:
            env["receipt"] = RECEIPTS[0]
        elif r < 0.1:
            env["trust"] = "primary"
        elif r < 0.15:
            del env[rng.choice(["estimate_seconds", "job", "poll", "request"])]
        text = json.dumps(env, indent=rng.choice([None, 1]))
        if rng.random() < 0.05:
            text = text.replace(f'"estimate_seconds": {env.get("estimate_seconds")}', '"estimate_seconds": 1.0')
        status = 202 if rng.random() < 0.9 else rng.choice([200, 201, 204])
    elif kind == "result":
        which = 0 if rng.random() < 0.75 else 1
        r = RECEIPTS[which]
        outcome = rng.choice(["ok", "stale", "not_covered"])
        if outcome == "not_covered":
            env, status = {"outcome": "not_covered"}, 404
        else:
            env, status = {"outcome": outcome, "receipt": r, "trust": "primary"}, 200
            if outcome == "stale":
                env["age_seconds"] = 60
        text = json.dumps(env, indent=rng.choice([None, 1]))
    else:
        outcome = rng.choice(["bad_request", "bad_request", "error"])
        env, status = {"error": "E_JOB_UNKNOWN", "outcome": outcome}, 400 if outcome == "bad_request" else 500
        text = json.dumps(env)
    return {"id": f"jobs/{i:04d}-{kind}-{'polled' if polled else 'cell'}", "kind": "envelope",
            "description": "spec-0.4.1: pending and job results", "valid": True, "input": text, "status": status,
            "keys": KEYS, "request": request}


MESH = "mesh.example.org"
MB = f"https://{MESH}"
ENDPOINTS = {"blob": f"{MB}/blob/{{sha256}}", "cell": f"{MB}/cell/{{cell}}", "cells": f"{MB}/cells",
             "descriptor": f"{MB}/descriptor/{{hash}}", "explain": f"{MB}/explain/{{cell}}", "find": f"{MB}/find",
             "jobs": f"{MB}/jobs/{{job}}", "manifest": f"{MB}/manifest/{{slice_id}}/{{members_hash}}",
             "receipt": f"{MB}/receipt/{{hash}}", "slice": f"{MB}/slice/{{cell}}", "verify": f"{MB}/verify"}
OPTIONAL = ["blob", "cells", "explain", "find", "slice", "verify"]


def mesh(i):
    endpoints = {k: v for k, v in ENDPOINTS.items() if k not in OPTIONAL or rng.random() < 0.7}
    doc = {"bindings": f"{MB}/bindings", "endpoints": endpoints, "host": MESH, "proto": canon.PROTO}
    keydoc = {"host": MESH, "keys": [KEY], "proto": canon.PROTO}
    labels = []
    for _ in range(rng.choice([0, 0, 1, 1, 2])):
        m = rng.randrange(14)
        labels.append(str(m))
        name = rng.choice(sorted(endpoints)) if endpoints else "cell"
        if m == 0:
            doc["host"] = rng.choice(["other.example.org", "MESH.example.org", MESH + "."])
        elif m == 1:
            doc["proto"] = rng.choice(["datumesh/2", "Datumesh/1", 1])
        elif m == 2:
            keydoc["host"] = "other.example.org"
        elif m == 3:
            keydoc["proto"] = "datumesh/2"
        elif m == 4 and name in endpoints:
            endpoints[name] = endpoints[name].replace(MESH, rng.choice(["other.example.org", MESH + ":8443", "user@" + MESH]))
        elif m == 5:
            doc["bindings"] = rng.choice(["https://other.example.org/bindings", f"http://{MESH}/bindings", f"https://{MESH}",
                                          None])
        elif m == 6 and name in endpoints:
            endpoints[name] = endpoints[name].split("/{")[0]  # placeholders dropped
        elif m == 7 and name in endpoints:
            endpoints[name] += rng.choice(["/{cell}", "?x={x}", "{"])
        elif m == 8:
            endpoints.pop(rng.choice(canon.MESH_REQUIRED), None)
        elif m == 9:
            endpoints["x_" + rng.choice(["graphql", "status"])] = rng.choice([f"{MB}/graphql", 7, "https://elsewhere.example/x"])
            doc["x_note"] = rng.choice(["beta", {"a": 1}, None])
        elif m == 10:
            doc["endpoints"] = rng.choice([[], "none", None])
        elif m == 11 and name in endpoints:
            endpoints[name] = rng.choice([7, None, f"{MB}/" + "x" * 520 + "/{cell}"])
        elif m == 12:
            keydoc["keys"] = []
        else:
            labels[-1] += "-text"
    text = json.dumps({k: v for k, v in doc.items() if v is not None}, indent=rng.choice([None, 2]))
    if labels and labels[-1].endswith("-text"):
        text = rng.choice([text[:-1], "[]", text.replace('"host"', '"host": "x", "host"', 1), "﻿" + text])
    env = {"keys": {"https": {"status": 200, "body": json.dumps(keydoc)}}, "mesh": {"https": {"status": 200, "body": text}}}
    r = rng.random()
    if r < 0.04:
        env["mesh"]["https"] = {"status": rng.choice([404, 500, "200", "error"])}
    elif r < 0.07:
        env["keys"]["https"] = {"status": rng.choice([404, "error"])}
    elif r < 0.09:
        env["mesh"]["https"] = {"status": 200}
    return {"id": f"mesh-fuzz/{i:04d}-{'-'.join(labels) or 'clean'}", "kind": "mesh",
            "description": "spec-0.4.1: mesh document resolution", "valid": True, "host": MESH, "env": env}


for i in range(N):
    print(json.dumps(jobs(i)))
for i in range(N):
    print(json.dumps(mesh(i)))
