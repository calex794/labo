//! LABO TIME-01 / TIME-02. Deterministic arithmetic and state-machine model,
//! NOT real RTC measurements, external time, deployed Akula, or real persistence.
//! After power loss without a running RTC, retained NVM is a lower bound ONLY.
use ed25519_dalek::{Signature, SigningKey, Signer, Verifier};
use sha2::{Digest, Sha256};

const DAYS:[i64;5]=[1,7,30,90,365];
const PPM:[i64;4]=[1,10,50,100];
const PERIOD:[i64;4]=[600,1200,3600,86400];
const SKEW_SIGN:[i64;2]=[-1,1];
const START:i64=1_800_000_000;
const SIGN_DOMAIN:&[u8]=b"LABO-TIME02-BOUND-NOT-WOW-V1\0";

fn floor_div(n:i64,d:i64)->i64 { n.div_euclid(d) }
fn error_ceiling(seconds:i64,ppm:i64)->i64 {
    (seconds*ppm+999_999)/1_000_000
}
fn matching(true_time:i64,estimate:i64,period:i64,neighbor:bool)->bool {
    let delta=(floor_div(true_time,period)-floor_div(estimate,period)).abs();
    delta <= if neighbor {1} else {0}
}
fn required_radius(true_time:i64,estimate:i64,period:i64)->i64 {
    (floor_div(true_time,period)-floor_div(estimate,period)).abs()
}
fn time01() {
    println!("# TIME-01-ARITHMETIC-NOT-MEASURED");
    for days in DAYS {
        for ppm in PPM {
            let delta=error_ceiling(days*86400,ppm);
            for period in PERIOD {
                let mut strict=0;let mut adjacent=0;let mut max_radius=0;
                // Sweep across the phase relative to rotation boundary, not just
                // one favorable fixed timestamp.
                for phase in 0..period {
                    let actual=START+days*86400+phase;
                    for sign in SKEW_SIGN {
                        let estimated=actual+sign*delta;
                        strict+=usize::from(matching(actual,estimated,period,false));
                        adjacent+=usize::from(matching(actual,estimated,period,true));
                        max_radius=max_radius.max(required_radius(actual,estimated,period));
                    }
                }
                let samples=2*period;
                println!("{{\"schema\":\"labo-time01-v1\",\"days\":{},\"ppm\":{},\"period_seconds\":{},\"max_drift_seconds\":{},\"strict_success\":{},\"adjacent_success\":{},\"samples\":{},\"max_required_radius\":{},\"client_hmac_budget_adjacent\":3,\"claim\":\"arithmetic-assumption\"}}",days,ppm,period,delta,strict,adjacent,samples,max_radius);
            }
        }
    }
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum Clock { Good, Bounded, Uncertain, Conflict }
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct Durable { watermark:i64, generation:u64, checkpoint:u64, pending_slots:u32 }
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct Recovered { clock:Clock, watermark:i64, pending_slots:u32, online_tag:bool, can_fetch_expiring:bool, can_fetch_timeless:bool, can_store_unbounded:bool }
fn restore(saved:Durable,rtc:Option<i64>,pinned_checkpoint:Option<u64>)->Recovered {
    let stale=pinned_checkpoint.is_some_and(|v|saved.checkpoint<v);
    let rtc_bad=rtc.is_some_and(|t|t<saved.watermark);
    let clock=if stale||rtc_bad {Clock::Conflict}
        else if rtc.is_some(){Clock::Bounded}else{Clock::Uncertain};
    Recovered {clock,watermark:saved.watermark,pending_slots:saved.pending_slots,
        online_tag:matches!(clock,Clock::Good|Clock::Bounded),
        can_fetch_expiring:matches!(clock,Clock::Good|Clock::Bounded),
        can_fetch_timeless:clock!=Clock::Conflict,
        can_store_unbounded:clock!=Clock::Conflict,
    }
}
fn witness_key()->SigningKey {
    let bytes:[u8;32]=Sha256::digest(b"LABORATORY-PREDICTABLE-TIME02-WITNESS").into();
    SigningKey::from_bytes(&bytes)
}
fn signed_bytes(nonce:&[u8;16],generation:u64,checkpoint:u64,lo:i64,hi:i64)->Vec<u8>{
    let mut v=SIGN_DOMAIN.to_vec();
    v.extend_from_slice(nonce);v.extend_from_slice(&generation.to_be_bytes());
    v.extend_from_slice(&checkpoint.to_be_bytes());v.extend_from_slice(&lo.to_be_bytes());
    v.extend_from_slice(&hi.to_be_bytes());v
}
struct TimeEvidence{nonce:[u8;16],generation:u64,checkpoint:u64,lo:i64,hi:i64,sig:Signature}
fn attest(k:&SigningKey,nonce:[u8;16],generation:u64,checkpoint:u64,lo:i64,hi:i64)->TimeEvidence{
    let sig=k.sign(&signed_bytes(&nonce,generation,checkpoint,lo,hi));
    TimeEvidence{nonce,generation,checkpoint,lo,hi,sig}
}
fn validate(e:&TimeEvidence,k:&SigningKey,nonce:&[u8;16],saved:&Durable,pin:Option<u64>)->bool {
    e.nonce==*nonce && e.generation==saved.generation
        && e.checkpoint>=saved.checkpoint
        && pin.is_none_or(|min|e.checkpoint>=min)
        && e.lo<=e.hi && e.lo>=saved.watermark
        && k.verifying_key().verify(&signed_bytes(&e.nonce,e.generation,e.checkpoint,e.lo,e.hi),&e.sig).is_ok()
}
fn time02() {
    println!("# TIME-02-SYNTHETIC-STATE-NOT-REAL-IO");
    let saved=Durable{watermark:START,generation:22,checkpoint:40,pending_slots:1};
    let nonce=[7u8;16];let k=witness_key();
    let evidence=attest(&k,nonce,22,40,START+30*86400,START+30*86400+10);
    let cases=[
        ("power_loss_no_rtc",None,None),
        ("retained_rtc",Some(START+30*86400),None),
        ("rtc_rollback",Some(START-3600),None),
        ("snapshot_rollback_detected",None,Some(41)),
        ("snapshot_without_external_pin",None,None),
    ];
    for (name,rtc,pin) in cases{
        let state=restore(saved,rtc,pin);
        println!("{{\"schema\":\"labo-time02-v1\",\"case\":\"{}\",\"clock\":\"{:?}\",\"tag_enabled\":{},\"expiring_fetch_enabled\":{},\"timeless_fetch_enabled\":{},\"store_without_deadline_enabled\":{},\"pending_slots\":{},\"watermark\":{},\"external_evidence_valid\":{},\"claim\":\"synthetic-state-no-real-disk\"}}",
        name,state.clock,state.online_tag,state.can_fetch_expiring,state.can_fetch_timeless,state.can_store_unbounded,state.pending_slots,state.watermark,
        validate(&evidence,&k,&nonce,&saved,pin));
    }
}
fn main(){
    let arg=std::env::args().nth(1).unwrap_or_else(||"all".into());
    match arg.as_str() {"time01"=>time01(),"time02"=>time02(),"all"=>{time01();time02();},_=>{eprintln!("use time01|time02|all");std::process::exit(2)}}
}
#[cfg(test)]
mod tests{
use super::*;
#[test]fn drift_calculation(){assert_eq!(error_ceiling(30*86400,50),130);assert_eq!(error_ceiling(30*86400,1),3);}
#[test]fn short_drift_window(){let t=START+30*86400;assert!(matching(t,t,1200,false));assert!(!matching(t,t+3600,1200,true));}
#[test]fn large_drift_not_silently_accepted(){let t=START+30*86400;assert!(!matching(t,t+30*86400,86400,true));}
#[test]fn no_rtc_is_unknown_not_fake_utc(){let saved=Durable{watermark:START,generation:1,checkpoint:1,pending_slots:2};let a=restore(saved,None,None);assert_eq!(a.clock,Clock::Uncertain);assert!(!a.online_tag);assert!(!a.can_fetch_expiring);assert!(a.can_fetch_timeless);assert_eq!(a.pending_slots,2);}
#[test]fn pinned_rollback_quarantines(){let saved=Durable{watermark:START,generation:1,checkpoint:1,pending_slots:2};let a=restore(saved,None,Some(2));assert_eq!(a.clock,Clock::Conflict);assert!(!a.can_store_unbounded);}
#[test]fn older_rtc_is_conflict(){let s=Durable{watermark:START,generation:1,checkpoint:1,pending_slots:2};assert_eq!(restore(s,Some(START-1),None).clock,Clock::Conflict);}
#[test]fn signed_nonce_and_key_enforced(){let k=witness_key();let saved=Durable{watermark:START,generation:3,checkpoint:11,pending_slots:1};let e=attest(&k,[1;16],3,11,START+2,START+10);assert!(validate(&e,&k,&[1;16],&saved,None));assert!(!validate(&e,&k,&[2;16],&saved,None));let other=SigningKey::from_bytes(&[9;32]);assert!(!validate(&e,&other,&[1;16],&saved,None));}
#[test]fn signed_lie_is_not_proven_true(){let k=witness_key();let saved=Durable{watermark:START,generation:3,checkpoint:11,pending_slots:1};let e=attest(&k,[1;16],3,11,START+10000,START+10010);assert!(validate(&e,&k,&[1;16],&saved,None));}
#[test]fn replay_and_old_checkpoint_rejected(){let k=witness_key();let saved=Durable{watermark:START,generation:3,checkpoint:11,pending_slots:1};let e=attest(&k,[1;16],3,11,START,START+10);assert!(!validate(&e,&k,&[1;16],&saved,Some(12)));}
}
