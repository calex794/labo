#!/usr/bin/env python3
"""EXP-018 stage 1: causal, durable gateway upload and receipt-return model.

Real observations: time-stamped human contacts only. Offline windows, gateways,
internet, mailbox polling and return markers are synthetic. Return markers are
NOT signed/verified W4 records.
"""
from dataclasses import dataclass
from collections import defaultdict

CLAIM = "synthetic-offline-gateways-and-receipt-markers-not-real-w4"


@dataclass(frozen=True)
class Window:
    start: int
    stop: int

    def __post_init__(self):
        if not (isinstance(self.start, int) and isinstance(self.stop, int)
                and 0 <= self.start < self.stop):
            raise ValueError("invalid offline window")

    def covers(self, tick):
        return self.start <= tick < self.stop


def offline(tick, windows):
    return any(w.covers(tick) for w in windows)


def validate_schedules(radio_down, internet_down, disk_loss):
    for schedule in (radio_down, internet_down, disk_loss):
        for node, windows in schedule.items():
            if not isinstance(node, int) or node < 0 or not isinstance(windows, (tuple, list)):
                raise ValueError("invalid gateway schedule")
            if any(not isinstance(w, Window) for w in windows):
                raise ValueError("invalid gateway interval")


def observed_while_awake(events, radio_down):
    """Only remove contacts that are physically impossible under the schedule."""
    out = []
    for event in events:
        tick, left, right = event[:3]
        if not (offline(tick, radio_down.get(left, ())) or
                offline(tick, radio_down.get(right, ()))):
            out.append(event)
    return out


def next_available(start, deadline, windows):
    """Only future state transition times, never a routing forecast."""
    t = start
    while t < deadline:
        overlapping = [w.stop for w in windows if w.covers(t)]
        if not overlapping:
            return t
        t = max(overlapping)
    return None


def recovery_outcomes(jobs, direct_ticks, stored_ticks, storage_gateways, *,
                      ttl, pickup_period, internet_down=None, disk_loss=None,
                      receipt_contacts=(), receipt_internet_delay=None):
    """Produce recipient and source milestones without conflating custody.

    The direct path is a recipient contact, otherwise the accepted mail requires
    a durable stored copy, an available uplink and strictly later mailbox poll.
    Receipt is separate: observed destination-to-source encounter after acceptance
    or an explicitly enabled, delayed synthetic Internet return.
    """
    internet_down = internet_down or {}
    disk_loss = disk_loss or {}
    validate_schedules({}, internet_down, disk_loss)
    if not (isinstance(ttl, int) and ttl > 0 and isinstance(pickup_period, int)
            and pickup_period > 0 and
            len(jobs) == len(direct_ticks) == len(stored_ticks) == len(storage_gateways)):
        raise ValueError("invalid recovery vectors")
    if receipt_internet_delay is not None and (
            not isinstance(receipt_internet_delay, int) or receipt_internet_delay < 1):
        raise ValueError("invalid simulated receipt delay")
    chronological = sorted(receipt_contacts)
    accepted, confirmed, uploaded, channels = [], [], [], []
    for mid, ((src, dst, created, _kind), direct, stored, node) in enumerate(
            zip(jobs, direct_ticks, stored_ticks, storage_gateways)):
        deadline = created + ttl
        if direct is not None and not (created <= direct < deadline):
            raise ValueError("invalid direct delivery timestamp")
        if stored is not None and (not isinstance(stored, int) or not
                                  (created <= stored < deadline) or node is None):
            raise ValueError("invalid stored gateway provenance")
        up = None
        if stored is not None:
            losses = disk_loss.get(node, ())
            # Upload may complete within the same 20-second contact tick
            # AFTER durable local commit; this matches EXP-015's healthy
            # always-online control while poll-on-exact-boundary stays strict.
            uplink = next_available(stored, deadline, internet_down.get(node, ()))
            if uplink is not None and not any(stored < w.start <= uplink
                                              for w in losses):
                up = uplink
        mail = None
        if up is not None:
            # Mailbox checks begin at created+period and at exact intervals;
            # a deposit on a poll tick is processed at the next poll.
            k = (up - created) // pickup_period + 1
            candidate = created + k * pickup_period
            if candidate < deadline:
                mail = candidate
        if direct is not None and (mail is None or direct <= mail):
            recipient, channel = direct, "observed-contact-synthetic-recipient"
        else:
            recipient, channel = mail, ("synthetic-mailbox-poll" if mail is not None else None)
        source_knows = None
        if recipient is not None:
            # Only a strictly later meeting can carry the synthetic receipt.
            via_contact = next((tick for tick, a, b in chronological
                                if tick > recipient and {a, b} == {src, dst}), None)
            via_internet = (recipient + receipt_internet_delay
                            if receipt_internet_delay is not None and channel ==
                               "synthetic-mailbox-poll" else None)
            possible = [t for t in (via_contact, via_internet) if t is not None]
            source_knows = min(possible) if possible else None
        accepted.append(recipient)
        confirmed.append(source_knows)
        uploaded.append(up)
        channels.append(channel)
        if source_knows is not None and (recipient is None or source_knows <= recipient):
            raise AssertionError("source confirmed before recipient")
    return dict(claim=CLAIM, gateway_stored=list(stored_ticks),
                mailbox_uploaded=uploaded, recipient_stored=accepted,
                source_confirmed=confirmed, delivery_channel=channels,
                missing_receipt=sum(a is not None and b is None
                                    for a, b in zip(accepted, confirmed)))
