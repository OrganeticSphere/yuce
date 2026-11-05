"""A reader of the audit server: the loop an agent runs, with your model in one function.

usage: python reader.py 127.0.0.1:8787 <token>
"""
import json
import sys

import yuce

REPAIRS = 3


def ask_model(prompt: str) -> str:
    """Give the directive to your model and return its reply: one JSON object per line, as the directive asks."""
    raise NotImplementedError("call your model here")


def lines_of(reply: str) -> list[dict]:
    return [json.loads(line) for line in reply.splitlines() if line.strip().startswith("{")]


def work(agent: yuce.Client) -> None:
    while True:
        task = agent.acquire(max_wait_ms=10_000)
        if task["status"] in ("COMPLETE", "DONE"):
            return
        if task["status"] != "DIRECTIVE":
            continue
        lines = lines_of(ask_model(task["prompt"]))
        answer = agent.submit(task["task_id"], lines)
        for _ in range(REPAIRS):
            if answer["status"] != "REPAIR_REQUIRED":
                break
            # the kernel kept the lines before the refused one: ask again with its reason, and send the rest
            print("refused:", answer.get("error"))
            lines = lines_of(ask_model(f"{task['prompt']}\n\nThe kernel refused a line: {json.dumps(answer.get('error'))}\nSend the lines again from that one."))
            answer = agent.submit(task["task_id"], lines)
        if answer["status"] == "REPAIR_REQUIRED":
            agent.release(task["task_id"])


if __name__ == "__main__":
    with yuce.Client(sys.argv[1], sys.argv[2]) as reader:
        print("reading as", reader.subject)
        work(reader)
