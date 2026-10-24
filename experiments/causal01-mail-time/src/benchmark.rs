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
}
