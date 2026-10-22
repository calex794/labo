"""EXP-011 offline parser and causal comparison invariants; no network needed."""
import io
from pathlib import Path
import tempfile
import unittest
import zipfile

from exp011_real_contacts import (
    SAMPLE_SECONDS, git_blob_sha, unzip_tij, parse_real_tij,
    choose_letters, pick_study_days, phase_jobs, routine_shift,
    evaluate_real_contacts,
)


def fixture():
    # Five measured days, 60 recorded contacts per day, same time semantics
    # as the real source; no human contact data is invented for published runs.
    lines = []
    for day in range(5):
        for slot in range(60):
            left = slot % 5
            right = (left + (1 if day < 3 else 2)) % 5
            if left == right:
                right = (right + 1) % 5
            t = day * 86400 + 32400 + slot * SAMPLE_SECONDS
            lines.append(f'{t}\t{10+left}\t{10+right}')
    return parse_real_tij('\n'.join(lines))


class RealContactTests(unittest.TestCase):
    def test_git_blob_pin_uses_correct_header(self):
        self.assertEqual(git_blob_sha(b'hello'),
                         'b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0')

    def test_zip_contract(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, mode='w') as z:
            z.writestr('workplace_InVS_tij.dat', '20\t1\t2\n40\t2\t3\n60\t3\t4')
        text = unzip_tij(archive.getvalue())
        self.assertEqual(len(parse_real_tij(text)['events']), 3)
        with self.assertRaises(ValueError):
            unzip_tij(b'not a zip archive')

    def test_inverse_pairs_are_deduplicated_and_chronological(self):
        data = parse_real_tij('20 1 2\n20 2 1\n40 3 2\n60 3 4')
        self.assertEqual(data['record_count'], 3)
        self.assertEqual([e[0] for e in data['events']], [0, 1, 2])
        self.assertEqual(data['participant_count'], 4)
        self.assertTrue(all(e[4] == 20000 for e in data['events']))

    def test_rejects_corrupted_or_non_20_second_contacts(self):
        for data in ('20 1 2\n40 2 3\n61 3 4',
                     '20 1 2\n40 2 3\n60 2 2',
                     '20 1 2\n40 2 3\n60 x 2'):
            with self.assertRaises(ValueError):
                parse_real_tij(data)

    def test_late_contact_shift_is_only_posthoc(self):
        data = fixture()
        train, early, late, days = pick_study_days(data)
        self.assertEqual((train, early, late), (0, 1, 3))
        change = routine_shift(data, early, late)
        self.assertGreater(change['new_late_edges'], 0)
        pairs_a = choose_letters(data, train, 12, 2, 2)
        # Changing all future contacts after training does not change the
        # addresses used for either period. Router must not see this analysis.
        saved = data['days'][late]
        data['days'][late] = [(t, a, b) for t,a,b in saved if a < b][:31]
        pairs_b = choose_letters(data, train, 12, 2, 2)
        self.assertEqual(pairs_a, pairs_b)
        jobs_early = phase_jobs(data, pairs_a, early)
        jobs_late = phase_jobs(data, pairs_b, late)
        self.assertEqual([(a,b,c) for a,b,_,c in jobs_early],
                         [(a,b,c) for a,b,_,c in jobs_late])
        self.assertLess(max(x[2] for x in jobs_early), min(x[2] for x in jobs_late))

    def test_same_pairs_and_global_k_across_policies(self):
        data = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            out = evaluate_real_contacts(data, Path(tmp), seeds=(42,),
                                         policies=('direct', 'prophet4'),
                                         letters_per_kind=2, ttl_hours=1)
            rows = out['rows']
            self.assertEqual(len(rows), 8)
            self.assertTrue((Path(tmp)/'real-contact-routing.csv').is_file())
            self.assertTrue((Path(tmp)/'report.md').is_file())
            for phase in ('early', 'late'):
                fingerprints = {r['job_digest'] for r in rows if r['phase'] == phase}
                self.assertEqual(len(fingerprints), 1)
            for row in rows:
                self.assertLessEqual(row['accepted_by_simulated_recipient'], row['oracle_reachable'])
                self.assertLessEqual(row['max_copies_seen'], row['k'])
                self.assertEqual(row['claim'], 'real-contact-graph-with-synthetic-routing-not-real-delivery')


if __name__ == '__main__':
    unittest.main()
