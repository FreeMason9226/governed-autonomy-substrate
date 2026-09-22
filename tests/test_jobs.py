from governed_autonomy import SQLiteJobStore, run_once


def test_jobs_are_idempotent_and_dead_letter_after_bounded_retries():
    store = SQLiteJobStore()
    first = store.enqueue({"action": "x"}, idempotency_key="same", max_attempts=2)
    assert store.enqueue({"action": "different"}, idempotency_key="same").job_id == first.job_id
    run_once(store, lambda _: (_ for _ in ()).throw(RuntimeError("no")), retry_delay=0)
    assert store.get(first.job_id).status == "queued"
    run_once(store, lambda _: (_ for _ in ()).throw(RuntimeError("no")), retry_delay=0)
    assert store.get(first.job_id).status == "dead_letter"


def test_successful_job_is_completed():
    store = SQLiteJobStore()
    job = store.enqueue({"value": 1}, idempotency_key="one")
    run_once(store, lambda payload: payload["value"])
    assert store.get(job.job_id).status == "succeeded"
