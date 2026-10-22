#!/usr/bin/env python3
"""EXP-011: unbiased paired routing comparison on published, anonymized contacts.

Real component: who was in face-to-face proximity to whom at which 20-second
intervals, recorded in a French office in 2013 (SocioPatterns, CC0).
Everything about Akula, volunteer permissions, BLE data transfers, radio,
application operation, and recipient acceptance is SIMULATED, not measured.
"""
import argparse
from collections import defaultdict
import csv
import hashlib
import io
import json
import math
from pathlib import Path
import random
import statistics
from urllib.request import Request, urlopen
import zipfile

from exp006_temporal_contacts import build_temporal_graph, earliest_delivery
from exp008_recipient_routes import simulate, policy_budget, CLAIM

SOURCE_REPO = 'SocioPatterns/sociopatterns.github.io'
SOURCE_COMMIT = 'd3fed34de6ca1cdeabe7c21dfc3475a19f46fe8f'
SOURCE_PATH = 'assets/data/workplace_InVS_tij.dat.zip'
SOURCE_GIT_BLOB = '268390bf5a3ab81b411a03edb02be59f4f172705'
DOWNLOAD_URL = f'https://raw.githubusercontent.com/{SOURCE_REPO}/{SOURCE_COMMIT}/{SOURCE_PATH}'
MIRROR_URL = 'https://sociopatterns.org/assets/data/workplace_InVS_tij.dat.zip'
SOURCE_PAGE = 'https://sociopatterns.org/datasets/contacts-in-a-workplace/'
SAMPLE_SECONDS = 20
DAY_SECONDS = 86_400
MAX_COMPRESSED = 1_000_000
MAX_UNCOMPRESSED = 8_000_000
MAX_CONTACTS = 500_000
POLICIES = ('direct', 'random4', 'spray4', 'prophet4', 'sequential4',
            'parallel4', 'oneplusone_predict4')
SEEDS = (21021, 21022, 21023)
CLAIM = 'real-contact-graph-with-synthetic-routing-not-real-delivery'


def git_blob_sha(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode('ascii') + b'\0' + data).hexdigest()


def fetch_pinned_zip(cache_dir, allow_download):
    """Fail closed on a modified upstream ZIP. Cache raw data locally, never git."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / 'workplace_InVS_tij.dat.zip'
    if not path.exists():
        if not allow_download:
            raise FileNotFoundError('Use --download to fetch the pinned upstream archive')
        errors = []
        for url in (DOWNLOAD_URL, MIRROR_URL):
            try:
                req = Request(url, headers={'User-Agent': 'LABO-EXP-011-academic-replay/1.0'})
                with urlopen(req, timeout=40) as response:
                    data = response.read(MAX_COMPRESSED + 1)
                if not (0 < len(data) <= MAX_COMPRESSED):
                    raise ValueError('source ZIP exceeds maximum compressed size')
                if git_blob_sha(data) != SOURCE_GIT_BLOB:
                    raise ValueError('download checksum differs from pinned Git blob')
                path.write_bytes(data)
                break
            except (OSError, ValueError) as error:
                errors.append(f'{url}: {error}')
        else:
            raise RuntimeError('Pinned SocioPatterns source not available: ' + '; '.join(errors))
    data = path.read_bytes()
    if not (0 < len(data) <= MAX_COMPRESSED) or git_blob_sha(data) != SOURCE_GIT_BLOB:
        raise ValueError('cached dataset has invalid pinned Git blob checksum')
    return data


def unzip_tij(archive):
    if not zipfile.is_zipfile(io.BytesIO(archive)):
        raise ValueError('not a valid ZIP archive')
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        candidates = [item for item in z.infolist()
                      if not item.is_dir() and item.filename.endswith('.dat')]
        if len(candidates) != 1:
            raise ValueError(f'expected one contact table, found {len(candidates)}')
        member = candidates[0]
        if (member.file_size > MAX_UNCOMPRESSED or member.file_size < 10
                or member.filename.startswith('/') or '..' in member.filename.split('/')):
            raise ValueError('invalid ZIP member size or path')
        payload = z.read(member)
        if len(payload) != member.file_size or len(payload) > MAX_UNCOMPRESSED:
            raise ValueError('ZIP member size mismatch')
        return payload.decode('ascii')


def parse_real_tij(raw):
    """Parse genuine t,i,j sightings, map anonymous IDs to dense IDs.

    No association with personal identity; these IDs are dataset-local labels.
    The source [t-20,t] measurement is represented as one hypothetical
    20,000-ms transfer opportunity at tick (t-t0)/20, not BLE handshaking.
    """
    records = set()
    for rownum, line in enumerate(raw.splitlines(), 1):
        if not line.strip() or line.startswith('#'):
            continue
        parts = line.split()
        if len(parts) != 3:
            raise ValueError(f'unexpected record shape on row {rownum}')
        try:
            t, a, b = map(int, parts)
        except ValueError as exc:
            raise ValueError(f'non-integer measurement on row {rownum}') from exc
        if (t < 0 or a < 0 or b < 0 or a == b or t % SAMPLE_SECONDS
                or len(records) >= MAX_CONTACTS):
            raise ValueError(f'invalid or excessive measurement on row {rownum}')
        if a > b:
            a, b = b, a
        records.add((t, a, b))
    if len(records) < 3:
        raise ValueError('too few valid contact samples')
    ordered = sorted(records)
    original_ids = sorted({v for _, a, b in ordered for v in (a, b)})
    index = {old: new for new, old in enumerate(original_ids)}
    first = ordered[0][0]
    events = [((t - first)//SAMPLE_SECONDS, index[a], index[b],
               'measured_face_to_face', 20_000) for t, a, b in ordered]
    days = defaultdict(list)
    for t, a, b in ordered:
        day = t // DAY_SECONDS
        days[day].append((t, index[a], index[b]))
    return {
        'events': events,
        'days': days,
        'original_ids': original_ids,
        'first_seconds': first,
        'last_seconds': ordered[-1][0],
        'record_count': len(ordered),
        'participant_count': len(original_ids),
    }


def pick_study_days(data):
    active = sorted(day for day, contacts in data['days'].items()
                    if len(contacts) >= 30)
    if len(active) < 4:
        raise ValueError('need at least four active measured days for chronology')
    # Hold out the first day for designing the letter cohort from *past* only.
    # Compare an early operational day to a late one, both with earlier contacts.
    first, last = active[1], active[-2]
    if first >= last:
        raise ValueError('dataset lacks distinct early/late measured days')
    return active[0], first, last, active


def choose_letters(data, training_day, seed, random_count=12, twohop_count=12):
    """Create target pairs based on BEFORE-first-deployment contact records.

    Two-hop cohort is a diagnostic selected with the training day only;
    it is not a uniformly random population sample and not routing oracle.
    """
    rng = random.Random(seed)
    trained = data['days'][training_day]
    members = sorted({v for _, a, b in trained for v in (a, b)})
    if len(members) < 4:
        raise ValueError('too few people visible before the test days')
    neighbors = defaultdict(set)
    for _, a, b in trained:
        neighbors[a].add(b)
        neighbors[b].add(a)
    possible = []
    for src in members:
        twohop = set()
        for middle in neighbors[src]:
            twohop.update(neighbors[middle])
        twohop.discard(src)
        twohop.difference_update(neighbors[src])
        possible.extend((src, dest) for dest in sorted(twohop))
    rng.shuffle(possible)
    twohop_pairs = list(dict.fromkeys(possible))[:twohop_count]
    if not twohop_pairs:
        raise ValueError('no past-two-hop validation targets')
    random_pairs = []
    for _ in range(random_count):
        src, dest = rng.sample(members, 2)
        random_pairs.append((src, dest))
    return [('random-uniform-among-training-participants', a, b)
            for a,b in random_pairs] + [('past-two-hop-chosen-before-evaluation', a, b)
                                     for a,b in twohop_pairs]


def routine_shift(data, early_day, late_day):
    """Post-hoc description only; NEVER used by router or pair selector."""
    def day_graph(day):
        pairs = set()
        nb = defaultdict(set)
        for _, a, b in data['days'][day]:
            pair = (min(a, b), max(a, b))
            pairs.add(pair)
            nb[a].add(b)
            nb[b].add(a)
        return pairs, nb
    e_pairs, e_nb = day_graph(early_day)
    l_pairs, l_nb = day_graph(late_day)
    both = set(e_nb) & set(l_nb)
    jaccard = []
    for node in both:
        a, b = e_nb[node], l_nb[node]
        jaccard.append(len(a & b)/len(a | b))
    return {
        'early_edges': len(e_pairs), 'late_edges': len(l_pairs),
        'persisting_edges': len(e_pairs & l_pairs),
        'new_late_edges': len(l_pairs - e_pairs),
        'disappeared_early_edges': len(e_pairs - l_pairs),
        'shared_participants': len(both),
        'mean_neighbor_jaccard': round(statistics.fmean(jaccard), 5) if jaccard else None,
        'late_new_edge_fraction': round(len(l_pairs - e_pairs)/len(l_pairs), 5) if l_pairs else None,
    }


def phase_jobs(data, chosen_pairs, day):
    first_sec = min(t for t, _, _ in data['days'][day])
    base = (first_sec - data['first_seconds'])//SAMPLE_SECONDS + 30
    return [(src, dest, base + (i%6)*5, group)
            for i, (group, src, dest) in enumerate(chosen_pairs)]


def evaluate_real_contacts(data, output, *, seeds=SEEDS, policies=POLICIES,
                           ttl_hours=8, letters_per_kind=12,
                           decay_half_life_hours=24):
    if not (1 <= ttl_hours <= 48 and 1 <= decay_half_life_hours <= 240):
        raise ValueError('invalid TTL or forecast half-life')
    ttl_ticks = ttl_hours * 3600 // SAMPLE_SECONDS
    decay_per_tick = math.exp(-math.log(2) * SAMPLE_SECONDS /
                              (decay_half_life_hours * 3600))
    training, early_day, late_day, days = pick_study_days(data)
    shift = routine_shift(data, early_day, late_day)
    rows = []
    matched = []
    for seed in seeds:
        pairs = choose_letters(data, training, seed,
                               random_count=letters_per_kind,
                               twohop_count=letters_per_kind)
        for phase, day in (('early', early_day), ('late', late_day)):
            jobs = phase_jobs(data, pairs, day)
            max_tick = max(created for _, _, created, _ in jobs) + ttl_ticks - 1
            observed = [event for event in data['events'] if event[0] <= max_tick]
            oracle_graph = build_temporal_graph(observed)
            oracle = [earliest_delivery(oracle_graph, src, dst, created, ttl_ticks)
                      for src, dst, created, _ in jobs]
            digest = hashlib.sha256(repr(jobs).encode('ascii')).hexdigest()
            for policy in policies:
                result = simulate(observed, jobs, policy=policy, ttl=ttl_ticks,
                                  seed=seed, residents_per_wing=100_000,
                                  volunteer=lambda node: True,
                                  gateways=(), mailbox_authorized=False,
                                  observation_end=max_tick, oracle_ticks=oracle,
                                  forecast_decay=decay_per_tick,
                                  forecast_all_contacts=True)
                if result['claim'] != 'synthetic-routing-not-real-delivery':
                    raise AssertionError('unexpected simulator provenance')
                if result['max_copies_seen'] > policy_budget(policy):
                    raise AssertionError('budget exceeded')
                if result['max_radio_per_device_tick_ms'] > 6000:
                    raise AssertionError('radio budget exceeded')
                if any(x > 1 for x in result['accepted_count']):
                    raise AssertionError('duplicate recipient acceptance')
                if any(r is not None and (oracle[i] is None or r < oracle[i])
                       for i, r in enumerate(result['delivery_ticks'])):
                    raise AssertionError('noncausal accepted path')
                matched.append({'seed': seed, 'phase': phase, 'policy': policy,
                                'job_digest': digest, 'wire_bytes': result['wire_bytes'],
                                'recipient_accept_total': sum(x is not None for x in result['delivery_ticks'])})
                for category, rec in sorted(result['groups'].items()):
                    rows.append({
                        'source': 'SocioPatterns-workplace-2013',
                        'seed': seed, 'phase': phase, 'day': day,
                        'policy': policy, 'k': policy_budget(policy),
                        'category': category, 'letters': rec['letters'],
                        'oracle_reachable': rec['oracle_ble_reachable'],
                        'accepted_by_simulated_recipient': rec['recipient_accepted'],
                        'undelivered': rec['undelivered'],
                        'accepted_percent': rec['accepted_percent'],
                        'median_delivery_ticks': rec['median_delivery_ticks'],
                        'p95_delivery_ticks': rec['p95_delivery_ticks'],
                        'mean_elapsed_seconds_per_tick': SAMPLE_SECONDS,
                        'run_wire_bytes_all_categories': result['wire_bytes'],
                        'run_transmissions': result['transmissions'],
                        'max_copies_seen': result['max_copies_seen'],
                        'max_radio_per_device_tick_ms': result['max_radio_per_device_tick_ms'],
                        'tracked_target_count': len(set(j[1] for j in jobs)),
                        'job_digest': digest,
                        'claim': CLAIM,
                    })
            print('REAL_DAY_COMPLETE', phase, 'day', seed,
                  'samples', len(observed), 'letter_pairs', len(jobs), flush=True)
    if not rows:
        raise ValueError('empty real contact comparison')
    for seed in seeds:
        for phase in ('early', 'late'):
            sig = {r['job_digest'] for r in rows if r['seed'] == seed and r['phase'] == phase}
            if len(sig) != 1:
                raise AssertionError('policy-specific letter pairs leaked into matrix')
    output.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0])
    with (output / 'real-contact-routing.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    manifest = {
        'schema': 'labo-exp011-sociopatterns-v1', 'claim': CLAIM,
        'source': SOURCE_PAGE, 'repo': SOURCE_REPO,
        'commit': SOURCE_COMMIT, 'source_blob': SOURCE_GIT_BLOB,
        'licence': 'CC0-1.0', 'citation': 'M. Genois et al., Network Science 3, 326 (2015)',
        'sample_seconds': SAMPLE_SECONDS, 'measured_contacts': data['record_count'],
        'distinct_participants': data['participant_count'],
        'active_days': days, 'training_day': training,
        'early_day': early_day, 'late_day': late_day,
        'contact_change_posthoc_not_a_routing_input': shift,
        'ttl_hours': ttl_hours, 'forecast_half_life_hours': decay_half_life_hours,
        'seeds': list(seeds), 'policies': list(policies), 'rows': rows,
    }
    (output / 'real-contact-routing.json').write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    summary = [
        '# LABO EXP-011 - recipient routing on REAL workplace contact records', '',
        '**Only the time-stamped face-to-face contacts are measured.**',
        '**All BLE transmissions, application acceptance, opt-in, and routing are simulated.**',
        f'Source: {SOURCE_PAGE} (public-domain CC0; Genois et al. 2015).',
        f'{data["participant_count"]} anonymous IDs, {data["record_count"]} measured 20s contacts;',
        f'early recorded day {early_day}, late recorded day {late_day};',
        f'{shift["late_new_edge_fraction"]:.2%} of distinct late-day pairs not observed on early day.',
        'No GPS, no measured phone BLE transfer probability, no signed W4.',
        f'Expected radio goodput 64 kbit/s, hypothetical 6s/device/20s tick.',
        'No real gateways or verified consent: participants are assumed to volunteer',
        'for the routing-only comparison. All letter pairs are chosen before the',
        'first evaluation from participants seen on the training day.',
        'Two-hop diagnostic pairs are derived only from **prior** training-day contacts.',
        'Causal forecasts store up to 16 entries per node without future addressee hints.',
        'Policies see old encounters, not future samples or post-hoc change statistics.',
        f'Routing forecast score half-life: {decay_half_life_hours} h (assumed), TTL {ttl_hours} h.',
        f'Equals K=4 for all policies except direct K=1.',
        'Run-wide wire bytes are repeated per category row and MUST NOT be summed.', '',
        '| Period | Category | Strategy (K) | Accepted % | Oracle % | Total run bytes / seed |',
        '|---|---|---|---:|---:|---:|',
    ]
    for phase in ('early', 'late'):
        for category in sorted(set(r['category'] for r in rows)):
            for policy in policies:
                sample = [r for r in rows if r['phase']==phase and
                          r['category']==category and r['policy']==policy]
                accepted = sum(r['accepted_by_simulated_recipient'] for r in sample)
                count = sum(r['letters'] for r in sample)
                oracle_num = sum(r['oracle_reachable'] for r in sample)
                total_bytes = statistics.fmean(r['run_wire_bytes_all_categories'] for r in sample)
                summary.append(f'| {phase} | {category} | {policy} ({policy_budget(policy)}) | '
                               f'{100*accepted/count:.2f}% | {100*oracle_num/count:.2f}% | '
                               f'{total_bytes:.0f} |')
    summary += ['', 'Interpretation: this dataset records close human encounters with',
                'wearable sensors, NOT actual smartphone BLE contact or packet transfers.',
                'Zero advantage is an informative negative result; small sample and day',
                'selection are not an estimate for a 200k-phone campus.',
                'The train-day cohort selection biases the two-hop diagnostic subset.',
                'K1 direct is a baseline, NOT an equal-resource comparison to K4.', '']
    (output / 'report.md').write_text('\n'.join(summary), encoding='utf-8')
    print('EXP011_COMPLETE', len(rows), 'category rows', len(seeds), 'seeds', flush=True)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, default=Path('results/real-sociopatterns-cache'))
    parser.add_argument('--output', type=Path, default=Path('results/exp011'))
    parser.add_argument('--download', action='store_true')
    parser.add_argument('--seeds', nargs='+', type=int, default=list(SEEDS))
    parser.add_argument('--letters-per-kind', type=int, default=12)
    parser.add_argument('--ttl-hours', type=int, default=8)
    parser.add_argument('--forecast-half-life-hours', type=int, default=24)
    args = parser.parse_args()
    if not (1 <= args.letters_per_kind <= 100 and 1 <= len(args.seeds) <= 20
            and all(0 <= s <= 2**32 for s in args.seeds)):
        parser.error('invalid sample/seed count')
    archive = fetch_pinned_zip(args.cache, args.download)
    data = parse_real_tij(unzip_tij(archive))
    evaluate_real_contacts(data, args.output, seeds=args.seeds,
                           ttl_hours=args.ttl_hours,
                           letters_per_kind=args.letters_per_kind,
                           decay_half_life_hours=args.forecast_half_life_hours)


if __name__ == '__main__':
    main()
