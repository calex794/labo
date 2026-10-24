//! Separate-process memory and latency microbenchmarks for temporal caching.
//! RSS includes runtime, maps, signatures and allocator, not only the cache.
//! Multiple GitHub-hosted runs are needed for robust performance comparisons.
use super::*;
use std::time::Instant;

pub fn run(mode:&str, rows:usize) {
    assert!((100..=20_000).contains(&rows), "rows must be in 100..=20000");
    let keys=[lab_key(928,0),lab_key(928,1),lab_key(928,2)];
    let authority=lab_key(928,210);
    let mut ledger=match mode {
        "incremental"=>Ledger::new(&keys),
        "bounded0"=>Ledger::new_bounded(&keys,0),
        "bounded32"=>Ledger::new_bounded(&keys,32),
        "bounded256"=>Ledger::new_bounded(&keys,256),
        "lru32"=>Ledger::new_bounded_lru(&keys,32),
        "lru256"=>Ledger::new_bounded_lru(&keys,256),
        _=>panic!("usage: --memory-benchmark incremental|bounded0|bounded32|bounded256|lru32|lru256 rows"),
    };

    let mut samples=Vec::with_capacity(rows);
    let mut last=None;
    let mut pinned=0usize;
    let mut signed_append_us=0u128;
    let mut pin_total_us=0u128;
    let mut pin_max_us=0u128;
    let started=Instant::now();
    for i in 0..rows {
        let actor=(i%3) as u8;
        let checkpoint=(i%100==0)||(i==rows-1);
        let event=ledger.draft(SCOPE,actor,1,last,
            if checkpoint {Kind::Checkpoint}else{Kind::Received},
            BASE_UTC+i as i64);
        let signed=sign(&keys[actor as usize],event);
        let append_started=Instant::now();
        let digest=ledger.append(signed).unwrap();
        signed_append_us+=append_started.elapsed().as_micros();
        if checkpoint {
            // The anchors are *assumed trusted* in this lab. They deliberately
            // constrain events in conflicting intervals as the sequence grows;
            // conflict state is not silently repaired.
            let lo=BASE_UTC+10*i as i64;
            let anchor=trusted_anchor(&authority,digest,lo,lo+5);
            let pin_started=Instant::now();
            assert!(ledger.pin_anchor(anchor,&authority.verifying_key()));
            let elapsed=pin_started.elapsed().as_micros();
            pin_total_us+=elapsed;
            pin_max_us=pin_max_us.max(elapsed);
            pinned+=1;
        }
        samples.push(digest);
        last=Some(digest);
    }
    let build_us=started.elapsed().as_micros();

    // Before timing queries, check against an oracle that never uses the
    // optimized temporal cache or indexed graph traversal.
    for ix in (0..rows).step_by((rows/24).max(1)) {
        let d=samples[ix];
        assert_eq!(ledger.bounds(d),ledger.bounds_reference(d),
            "mode {mode} oracle mismatch at {ix}");
    }
    let queries=rows/2;
    let started=Instant::now();
    let mut checksum=0u64;
    for i in 0..queries {
        // 90% hot-set queries, 10% uniformly dispersed cold queries. Same
        // deterministic workload across all four independent processes.
        let ix=if i%10==0{(i*17+59)%rows}
               else{rows-1-(i%24)};
        let value=std::hint::black_box(ledger.bounds(
            std::hint::black_box(samples[ix])
        ));
        checksum=checksum.wrapping_add(super::benchmark::bounds_code(value));
    }
    let query_us=started.elapsed().as_micros();
    let (derived_entries,derived_children,cache_entries,hits,misses,evictions)=
        if let Some(c)=&ledger.bounded {
            let c=c.borrow();
            (ledger.temporal.len(),
             ledger.children.values().map(|v|v.len()).sum::<usize>(),
             c.cache_len(),c.hits,c.misses,c.evictions)
        }else{
            (ledger.temporal.len(),
             ledger.children.values().map(|v|v.len()).sum::<usize>(),
             0,0,0,0)
        };
    let signed_events=ledger.events.len();
    let causal_edge_lists=ledger.cross_links.values().map(|v|v.len()).sum::<usize>();
    // Do not claim total memory is bounded: the signed history remains.
    println!("BENCH memory mode={} events={} anchors={} queries={} build_us={} append_total_us={} pin_total_us={} pin_max_us={} query_us={} signed_events={} cross_links={} temporal_entries={} temporal_children={} cache_entries={} hits={} misses={} evictions={} checksum={}",
        mode,rows,pinned,queries,build_us,signed_append_us,pin_total_us,pin_max_us,query_us,signed_events,
        causal_edge_lists,derived_entries,derived_children,cache_entries,hits,misses,evictions,checksum);
}
