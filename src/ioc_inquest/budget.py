"""A persisted per-provider request budget.

VirusTotal's free tier is four requests a minute and 500 a day. Until now
the tool discovered that limit by being refused, which costs a round trip
and produces a 429 the retry loop then patiently backs off from three times
-- and a batch or a pivot run walks into it immediately.

Two properties are what make this a table rather than a counter:

- It survives the process. A daily ceiling that resets every time someone
  runs the command is not a daily ceiling.
- It counts REQUESTS, not lookups. Nothing here is consulted on a cache
  hit; the call site asks only when it is about to make a real call.

The clock is injectable for one reason: the windows are 60 seconds and 24
hours wide, and a test that proved one of them rolls by waiting for it
would take a minute -- or a day -- per assertion.
"""

import sqlite3
import time
from pathlib import Path

from .cache import cache_path, open_db

#: VirusTotal's published free-tier limits. Named rather than inlined
#: because --ignore-budget's whole purpose is to say "my key is not this".
VT_PER_MINUTE = 4
VT_PER_DAY = 500

MINUTE_WINDOW = 60.0
DAY_WINDOW = 86400.0

RATE_EVENTS_DDL = (
    "CREATE TABLE IF NOT EXISTS rate_events ("
    " provider TEXT NOT NULL,"
    " at REAL NOT NULL)",
    "CREATE INDEX IF NOT EXISTS rate_events_provider_at"
    " ON rate_events (provider, at)",
)


class RateBudget:
    """How many requests a provider has left, and when it gets more.

    Lives in the response cache's database -- one more table in the file
    that is already there. A second file for a few dozen rows is a second
    thing to corrupt and a second thing to forget to delete.

    It does NOT ride on the ResponseCache object, though, and that is the
    point of the separate connection: `--no-cache` leaves that object with
    no connection at all, and `--no-cache` is precisely the mode in which
    every lookup is a real request and the budget matters most.

    Not atomic, deliberately. `allows()` and `record()` are two statements
    and a caller could be preempted between them, but nothing in this
    process ever is: only VirusTotal is gated, data_puller makes exactly one
    VT call per invocation, and run_batch is a serial `for ... await`. Two
    *processes* can both pass allows() before either records, overshooting
    by at most the number of them -- bounded, and absorbed by the server's
    own 429 and base_call's retry. A transaction here would buy nothing and
    cost a lock held across a network call.
    """

    def __init__(self, path=None, *, per_minute: int = VT_PER_MINUTE,
                 per_day: int = VT_PER_DAY, clock=time.time):
        if per_minute < 0 or per_day < 0:
            raise ValueError(
                "a rate budget cannot be negative; 0 means 'refuse every "
                f"call'. Got per_minute={per_minute}, per_day={per_day}"
            )
        self.per_minute = per_minute
        self.per_day = per_day
        self._clock = clock
        self._closed = False
        path = Path(path) if path else cache_path()
        self._conn = open_db(path, RATE_EVENTS_DDL, "rate budget")

    def _limits(self):
        """(limit, window) pairs. wait_seconds reports the longest wait any
        exceeded one imposes, so the order here decides nothing."""
        return ((self.per_minute, MINUTE_WINDOW), (self.per_day, DAY_WINDOW))

    def _check_open(self) -> None:
        """A closed budget is a bug, not a degraded one.

        Both states leave `_conn` None, and they must not answer alike:
        degraded means "the database let us down, carry on unbudgeted",
        while a call after close() means a caller kept a reference past the
        `finally` that closed it. Reading the second as the first would
        report an unlimited budget and be invisible -- so it raises, the way
        _require_provider does for the other reference mistake this codebase
        has actually made.
        """
        if self._closed:
            raise RuntimeError(
                "this RateBudget is closed -- whoever opened it has already "
                "run its finally block. A batch's budget outlives each "
                "individual run in it, so only the opener may close it."
            )

    def _degrade(self, error) -> None:
        """Drop a connection that opened cleanly and then started failing.

        open_db only covers the open. A file that is read-only, or locked by
        a second ioc-inquest, passes `CREATE TABLE IF NOT EXISTS` (it needs
        no write against a table that already exists) and raises on the first
        INSERT instead. Uncaught, that reached run() as a traceback for a
        single run -- and, worse, run_batch's per-indicator `except
        Exception` for a batch, turning a locked database into EXIT_NO_DATA
        on every line. Which is exactly the "answers nothing" outcome failing
        open exists to prevent, so the runtime path has to degrade the way
        the open path does.
        """
        print(f"Warning: the rate budget stopped working ({error}); "
              "continuing without one.")
        try:
            self._conn.close()
        except sqlite3.Error:
            pass  # already broken; there is nothing better to do
        self._conn = None

    def _since(self, provider: str, window: float, now: float) -> list[float]:
        """Every recorded call for `provider` inside `window`, oldest first.

        `now` is passed in rather than read here, so every window in one
        answer is measured against a single instant. Reading the clock per
        window let allows() and wait_seconds() disagree at the edge, and
        quietly required an injected clock to be idempotent.
        """
        return [
            row[0] for row in self._conn.execute(
                "SELECT at FROM rate_events WHERE provider = ? AND at > ?"
                " ORDER BY at",
                (provider, now - window),
            )
        ]

    def allows(self, provider: str) -> bool:
        """True when a request may be made right now.

        Fails OPEN when the database is unusable, having said so on stdout.
        A rate budget is a courtesy to a free tier, not a security control:
        the server is the authority, base_call already handles the 429 an
        over-quota key really returns, and the count is best-effort anyway --
        the user can delete the file or pass --ignore-budget. Refusing every
        lookup because a cache file is unreadable would turn a cosmetic local
        problem into a tool that cannot answer anything.
        """
        self._check_open()
        if self._conn is None:
            return True
        now = self._clock()
        try:
            return all(len(self._since(provider, window, now)) < limit
                       for limit, window in self._limits())
        except sqlite3.Error as e:
            self._degrade(e)
            return True

    def record(self, provider: str) -> None:
        """Charge one request against `provider`.

        Also drops everything older than the widest window: the table is
        otherwise append-only, and nothing below `now - DAY_WINDOW` can
        affect any answer this class gives.
        """
        self._check_open()
        if self._conn is None:
            return
        now = self._clock()
        try:
            self._conn.execute("INSERT INTO rate_events VALUES (?, ?)",
                               (provider, now))
            self._conn.execute("DELETE FROM rate_events WHERE at <= ?",
                               (now - DAY_WINDOW,))
            self._conn.commit()
        except sqlite3.Error as e:
            self._degrade(e)

    def wait_seconds(self, provider: str) -> float:
        """How long until `allows` turns True again. 0.0 when it already is.

        Measured from the OLDEST call in each exceeded window, not as a flat
        window width: four calls made 50 seconds ago free up in 10, and
        telling a user to wait a minute for a slot that arrives in 10
        seconds is a worse answer than no answer at all.

        A zero limit never frees up, and reports the full window rather than
        an infinity every caller would have to special-case -- the message
        this feeds says "retry in", and there is no honest finite number.
        """
        self._check_open()
        if self._conn is None:
            return 0.0
        now = self._clock()
        waits = [0.0]
        try:
            for limit, window in self._limits():
                calls = self._since(provider, window, now)
                if len(calls) < limit:
                    continue
                if limit == 0:
                    waits.append(window)
                    continue
                # The call that has to leave the window before there is room.
                # With `limit` allowed and n recorded, n - limit + 1 of them
                # must expire, so the last to do so sits at index n - limit --
                # the newest one when n == limit, and correctly earlier when a
                # cross-process race pushed n above it.
                waits.append(calls[len(calls) - limit] + window - now)
        except sqlite3.Error as e:
            self._degrade(e)
            return 0.0
        return max(waits)

    def close(self) -> None:
        """Idempotent, and never raises: it runs in `finally` blocks."""
        if self._conn:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass
            self._conn = None
        self._closed = True
