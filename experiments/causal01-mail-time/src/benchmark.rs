use super::*;
use std::time::Instant;
fn case(reference:bool,rows:usize)->(u128,u128,usize,usize){
 let keys=[lab_key(91,0),lab_key(91,1),lab_key(91,2)];
 let mut l=Ledger::new(&keys);
 let mut last=None;
 let mut samples=Vec::with_capacity(rows);
 let start=Instant::now();
 for i in 0..rows{
  let actor=(i%3) as u8;
  let e=l.draft(SCOPE,actor,1,last,Kind::Received,BASE_UTC+i as i64);
  let signed=sign(&keys[actor as usize],e);
  let d=if reference{l.append_reference(signed)}else{l.append(signed)}.unwrap();
  last=Some(d);samples.push(d);
 }
 let append_us=start.elapsed().as_micros();
 let start=Instant::now();
 let mut answers=0;
 for i in 0..samples.len(){
    let a=samples[i];
    let b=samples[(i*17+59)%samples.len()];
    answers+=usize::from(if reference{l.is_ancestor_reference(a,b)}else{l.is_ancestor(a,b)});
 }
 let ancestor_us=start.elapsed().as_micros();
 (append_us,ancestor_us,l.events.len(),answers)
}
pub fn run(){
 // Deterministic payloads, but wall times are noisy GitHub-hosted VM
 // measurements. Compare semantic outputs before quoting speedups.
 for rows in [100usize,300,600]{
  let baseline=case(true,rows);
  let optimized=case(false,rows);
  assert_eq!(baseline.2,optimized.2);
  assert_eq!(baseline.3,optimized.3);
  println!("BENCH causal rows={} reference_append_us={} optimized_append_us={} reference_ancestor_us={} optimized_ancestor_us={} events={} answered={}",
    rows,baseline.0,optimized.0,baseline.1,optimized.1,optimized.2,optimized.3);
 }
 for rows in [100usize,300,600] {
     let queries=rows*10;
     let (pins,pin_us,reference_us,cached_us,checksum)=temporal_case(rows,queries);
     println!("BENCH temporal rows={} queries={} checkpoints={} pin_total_us={} reference_query_us={} cached_query_us={} checksum={}",
        rows,queries,pins,pin_us,reference_us,cached_us,checksum);
 }
}


/// Compare repeated historical-time interval queries against unchanged
/// exhaustive-anchor reference, using identical signed event histories.
/// This measures query cost; pin maintenance is reported separately.
fn temporal_case(rows:usize,queries:usize)->(usize,u128,u128,u128,u64) {
    use std::hint::black_box;
    let keys=[lab_key(91,0),lab_key(91,1),lab_key(91,2)];
    let authority=lab_key(91,210);
    let mut ledger=Ledger::new(&keys);
    let mut last=None;
    let mut samples=Vec::with_capacity(rows);
    let mut pin_us=0u128;
    let mut pins=0usize;
    for i in 0..rows {
        let actor=(i%3) as u8;
        let is_checkpoint=i%50==0 || i==rows-1;
        let event=ledger.draft(SCOPE,actor,1,last,
            if is_checkpoint {Kind::Checkpoint}else{Kind::Received},
            BASE_UTC+i as i64);
        let digest=ledger.append(sign(&keys[actor as usize],event)).unwrap();
        if is_checkpoint {
            let earliest=BASE_UTC+10*i as i64;
            let proof=trusted_anchor(&authority,digest,earliest,earliest+5);
            let start=Instant::now();
            assert!(ledger.pin_anchor(proof,&authority.verifying_key()));
            pin_us+=start.elapsed().as_micros();
            pins+=1;
        }
        samples.push(digest);
        last=Some(digest);
    }
    for &event in &samples {
        assert_eq!(ledger.bounds(event),ledger.bounds_reference(event));
    }
    let start=Instant::now();
    let mut reference_checksum=0u64;
    for i in 0..queries {
        let d=samples[(i*17+59)%rows];
        // black_box prevents the Rust compiler from eliding repeated reads.
        let b=black_box(ledger.bounds_reference(black_box(d)));
        reference_checksum=reference_checksum.wrapping_add(bounds_code(b));
    }
    let reference_us=start.elapsed().as_micros();
    let start=Instant::now();
    let mut fast_checksum=0u64;
    for i in 0..queries {
        let d=samples[(i*17+59)%rows];
        let b=black_box(ledger.bounds(black_box(d)));
        fast_checksum=fast_checksum.wrapping_add(bounds_code(b));
    }
    let cached_us=start.elapsed().as_micros();
    assert_eq!(reference_checksum,fast_checksum,
               "cached time bound mismatch");
    (pins,pin_us,reference_us,cached_us,fast_checksum)
}

fn bounds_code(value:Bounds)->u64{
    match value {
        Bounds::OrderOnly=>0,
        Bounds::LowerOnly(v)=>1 ^ v as u64,
        Bounds::UpperOnly(v)=>2 ^ (v as u64).rotate_left(11),
        Bounds::Interval(lo,hi)=>3 ^ (lo as u64) ^ (hi as u64).rotate_left(17),
        Bounds::Conflict=>4,
    }
}
