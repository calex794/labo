"""LABO EXP-007 resource and temporal invariants."""
import unittest
from exp007_contact_capacity import simulate
from exp006_temporal_contacts import contact_events

class CapacityTests(unittest.TestCase):
    def simulate(self, contacts, jobs, **kwargs):
        return simulate(contacts, jobs, message_bytes=kwargs.pop('message_bytes',256),
                        goodput_kbps=kwargs.pop('goodput_kbps',64),
                        setup_ms=kwargs.pop('setup_ms',200),
                        envelope_bytes=kwargs.pop('envelope_bytes',64),
                        **kwargs)

    def test_two_timed_hops_and_no_same_tick_forwarding(self):
        jobs = [(0,2,0,'control')]
        same = self.simulate([(0,0,1,'contact',3000),(0,1,2,'contact',3000)],jobs)
        self.assertEqual(same['groups']['control']['delivered'],0)
        later = self.simulate([(0,0,1,'contact',3000),(1,1,2,'contact',3000)],jobs)
        self.assertEqual(later['groups']['control']['delivered'],1)
        self.assertEqual(later['individual_delivered_ticks'],[1])

    def test_short_encounter_does_not_transfer(self):
        job = [(0,1,0,'test')]
        q=self.simulate([(0,0,1,'x',350)],job,message_bytes=4096,goodput_kbps=8)
        self.assertEqual(q['groups']['test']['oracle_reachable'],1)
        self.assertEqual(q['groups']['test']['delivered'],0)
        self.assertGreater(q['capacity_blocked_attempts'],0)
        fast=self.simulate([(0,0,1,'x',350)],job,message_bytes=256,goodput_kbps=64)
        self.assertEqual(fast['groups']['test']['delivered'],1)

    def test_larger_message_can_fail_at_same_goodput(self):
        e=[(0,0,1,'x',1500)]
        j=[(0,1,0,'test')]
        small=self.simulate(e,j,message_bytes=256,goodput_kbps=8)
        huge=self.simulate(e,j,message_bytes=4096,goodput_kbps=8)
        self.assertEqual(small['groups']['test']['delivered'],1)
        self.assertEqual(huge['groups']['test']['delivered'],0)

    def test_one_copy_can_be_lost_to_wrong_relay(self):
        e=[(0,0,1,'x',2000),(1,0,2,'x',2000)]
        j=[(0,2,0,'test')]
        single=self.simulate(e,j,copy_limit=1)
        double=self.simulate(e,j,copy_limit=2)
        self.assertEqual(single['groups']['test']['delivered'],0)
        self.assertEqual(double['groups']['test']['delivered'],1)

    def test_shared_tick_airtime_limits_multiple_contacts(self):
        e=[(0,0,1,'x',1500),(0,0,2,'x',1500)]
        j=[(0,1,0,'test'),(0,2,0,'test')]
        free=self.simulate(e,j,radio_ms_per_tick=6000,message_bytes=1024,goodput_kbps=8)
        constrained=self.simulate(e,j,radio_ms_per_tick=1500,message_bytes=1024,goodput_kbps=8)
        self.assertEqual(free['groups']['test']['delivered'],2)
        self.assertEqual(constrained['groups']['test']['delivered'],1)

    def test_ttl_excludes_late_contact(self):
        e=[(10,0,1,'late',2000)]
        j=[(0,1,0,'test')]
        self.assertEqual(self.simulate(e,j,ttl=10)['groups']['test']['delivered'],0)
        self.assertEqual(self.simulate(e,j,ttl=11)['groups']['test']['delivered'],1)

    def test_no_interwing_teleportation_without_carriers(self):
        no_carrier=contact_events(2,15,7,False)
        with_carrier=contact_events(2,15,7,True)
        jobs=[(0,2000,0,'hub')]
        absent=self.simulate(no_carrier,jobs)
        active=self.simulate(with_carrier,jobs)
        self.assertEqual(absent['groups']['hub']['oracle_reachable'],0)
        self.assertEqual(absent['groups']['hub']['delivered'],0)
        self.assertEqual(active['groups']['hub']['oracle_reachable'],1)
        self.assertEqual(active['groups']['hub']['delivered'],1)

    def test_capacity_never_exceeds_oracle_or_copy_limit(self):
        e=[(0,0,1,'t',3000),(1,1,2,'t',3000),(2,2,3,'t',3000)]
        jobs=[(0,3,0,'test')]
        t=self.simulate(e,jobs,copy_limit=2)
        self.assertLessEqual(t['groups']['test']['delivered'],t['groups']['test']['oracle_reachable'])
        self.assertLessEqual(t['peak_total_copies'],2)

    def test_reproducible_for_same_inputs(self):
        e=contact_events(2,18,123,True)
        j=[(0,2000,0,'hub')]
        self.assertEqual(self.simulate(e,j),self.simulate(e,j))

    def test_negative_input_fails(self):
        with self.assertRaises(ValueError):
            self.simulate([],[(0,1,0,'test')],goodput_kbps=0)
        with self.assertRaises(ValueError):
            self.simulate([(0,1,1,'x',1200)],[(0,1,0,'test')])

if __name__=='__main__':unittest.main()