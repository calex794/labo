//! TIME-04: two OS processes, Noise IK over loopback TCP, signed UTC claims.
//! Real authenticated transport; synthetic time. Not Roughtime, NTS, QUIC,
//! verified physical operator independence or a production Akula protocol.
use ed25519_dalek::{Signature,Signer,SigningKey,Verifier};
use sha2::{Sha256,Digest};
use snow::{Builder,params::NoiseParams};
use std::{env,io::{Read,Write},net::{TcpListener,TcpStream},time::Duration};

const DOMAIN:&[u8]=b"LABO/TIME04/v1\0";
const GOOD_UTC:i64=1_802_592_000;
const PIN:u64=40;
const GENERATION:u64=22;
const CHALLENGE:[u8;16]=[0xA5;16]; // deterministic per scenario TEST ONLY.
const NOISE:&str="Noise_IK_25519_ChaChaPoly_BLAKE2s";

fn secret(name:&str)->[u8;32] {
 let mut h=Sha256::new();h.update(b"LABO-INSECURE-FIXTURE-ONLY");h.update(name.as_bytes());h.finalize().into()
}
fn noise_secret(name:&str)->[u8;32] { secret(&format!("noise/{name}")) }
fn noise_public(secret:[u8;32])->[u8;32] {
 let sk=x25519_dalek::StaticSecret::from(secret);
 x25519_dalek::PublicKey::from(&sk).to_bytes()
}
fn signer(name:&str)->SigningKey {SigningKey::from_bytes(&secret(&format!("sign/{name}")))}
fn message(nonce:&[u8;16],epoch:u64,checkpoint:u64,utc:i64)->Vec<u8>{
 let mut v=DOMAIN.to_vec();v.extend_from_slice(nonce);
 v.extend_from_slice(&epoch.to_be_bytes());v.extend_from_slice(&checkpoint.to_be_bytes());
 v.extend_from_slice(&utc.to_be_bytes());v
}
fn frame(stream:&mut TcpStream, bytes:&[u8])->Result<(),String>{
 if bytes.len()>4096 {return Err("too big".into())}
 stream.write_all(&(bytes.len() as u16).to_be_bytes()).map_err(|e|e.to_string())?;
 stream.write_all(bytes).map_err(|e|e.to_string())
}
fn read_frame(stream:&mut TcpStream)->Result<Vec<u8>,String>{
 let mut len=[0u8;2];stream.read_exact(&mut len).map_err(|e|e.to_string())?;
 let n=u16::from_be_bytes(len) as usize;
 if n>4096{return Err("oversize".into())}
 let mut buf=vec![0;n];stream.read_exact(&mut buf).map_err(|e|e.to_string())?;Ok(buf)
}
fn handshake(stream:&mut TcpStream,server:bool,wrong_server:bool)->Result<snow::TransportState,String>{
 let params=NOISE.parse::<NoiseParams>().map_err(|e|e.to_string())?;
 let server_secret=noise_secret(if wrong_server {"attacker"}else{"server"});
 let client_secret=noise_secret("client");
 let mut state=if server {
  Builder::new(params).local_private_key(&server_secret)
    .build_responder().map_err(|e|e.to_string())?
 } else {
  Builder::new(params).local_private_key(&client_secret)
   .remote_public_key(&noise_public(noise_secret("server")))
   .build_initiator().map_err(|e|e.to_string())?
 };
 let mut buf=[0u8;4096];
 if server {
  let first=read_frame(stream)?;
  state.read_message(&first,&mut buf).map_err(|e|e.to_string())?;
  let n=state.write_message(&[],&mut buf).map_err(|e|e.to_string())?;
  frame(stream,&buf[..n])?;
 } else {
  let n=state.write_message(&[],&mut buf).map_err(|e|e.to_string())?;
  frame(stream,&buf[..n])?;
  let second=read_frame(stream)?;
  state.read_message(&second,&mut buf).map_err(|e|e.to_string())?;
 }
 if !state.is_handshake_finished(){return Err("incomplete handshake".into())}
 state.into_transport_mode().map_err(|e|e.to_string())
}
fn send_encrypted(s:&mut TcpStream,t:&mut snow::TransportState,msg:&[u8])->Result<(),String>{
 let mut buf=[0u8;4096];let n=t.write_message(msg,&mut buf).map_err(|e|e.to_string())?;
 frame(s,&buf[..n])
}
fn recv_encrypted(s:&mut TcpStream,t:&mut snow::TransportState)->Result<Vec<u8>,String>{
 let wire=read_frame(s)?;let mut buf=[0u8;4096];let n=t.read_message(&wire,&mut buf).map_err(|e|e.to_string())?;
 Ok(buf[..n].to_vec())
}
fn serve(addr:&str,mode:&str)->Result<(),String>{
 let listener=TcpListener::bind(addr).map_err(|e|e.to_string())?;
 println!("READY");std::io::stdout().flush().map_err(|e|e.to_string())?;
 let (mut stream,_)=listener.accept().map_err(|e|e.to_string())?;
 stream.set_read_timeout(Some(Duration::from_secs(2))).map_err(|e|e.to_string())?;
 stream.set_write_timeout(Some(Duration::from_secs(2))).map_err(|e|e.to_string())?;
 let mut noise=handshake(&mut stream,true,mode=="wrong-noise-key")?;
 let req=recv_encrypted(&mut stream,&mut noise)?;
 if req.len()!=16+8+8{return Err("bad request".into())}
 let mut nonce=[0u8;16];nonce.copy_from_slice(&req[..16]);
 let mut epoch=u64::from_be_bytes(req[16..24].try_into().unwrap());
 let mut checkpoint=u64::from_be_bytes(req[24..32].try_into().unwrap());
 if mode=="replay"{nonce[0]^=0x1}
 if mode=="old-epoch"{epoch-=1}
 if mode=="rollback"{checkpoint-=1}
 let utc=if mode=="signed-lie"{GOOD_UTC+3600}else{GOOD_UTC};
 let mut signed=message(&nonce,epoch,checkpoint,utc);
 let signature=signer("server").sign(&signed);
 signed.extend_from_slice(&signature.to_bytes());
 if mode=="tamper"{signed[40]^=1;}
 if mode=="silent"{return Ok(())}
 send_encrypted(&mut stream,&mut noise,&signed)?;
 Ok(())
}
fn client(addr:&str)->Result<&'static str,String>{
 let mut stream=TcpStream::connect(addr).map_err(|e|e.to_string())?;
 stream.set_read_timeout(Some(Duration::from_secs(2))).map_err(|e|e.to_string())?;
 stream.set_write_timeout(Some(Duration::from_secs(2))).map_err(|e|e.to_string())?;
 let mut transport=handshake(&mut stream,false,false)?;
 let mut req=CHALLENGE.to_vec();req.extend_from_slice(&GENERATION.to_be_bytes());req.extend_from_slice(&PIN.to_be_bytes());
 send_encrypted(&mut stream,&mut transport,&req)?;
 let received=recv_encrypted(&mut stream,&mut transport)?;
 let expected_len=DOMAIN.len()+16+8+8+8+64;
 if received.len()!=expected_len{return Err("invalid signed response size".into())}
 let signature=Signature::from_slice(&received[received.len()-64..]).map_err(|e|e.to_string())?;
 signer("server").verifying_key().verify(&received[..received.len()-64],&signature).map_err(|_|"signature rejected")?;
 if &received[..DOMAIN.len()]!=DOMAIN{return Err("wrong domain".into())}
 let start=DOMAIN.len();
 if received[start..start+16]!=CHALLENGE {return Ok("REJECT_REPLAY")}
 let epoch=u64::from_be_bytes(received[start+16..start+24].try_into().unwrap());
 if epoch!=GENERATION{return Ok("REJECT_EPOCH")}
 let checkpoint=u64::from_be_bytes(received[start+24..start+32].try_into().unwrap());
 if checkpoint<PIN{return Ok("REJECT_ROLLBACK")}
 let utc=i64::from_be_bytes(received[start+32..start+40].try_into().unwrap());
 // A correct cryptographic signature does not establish correct UTC. Without
 // independent trusted bounds, never switch the clock or enable expiring IO.
 if utc<1_800_000_000{return Ok("REJECT_BEFORE_WATERMARK")}
 Ok("BOUND_SIGNED_UNTRUSTED_UTC")
}
fn main(){
 let args=env::args().collect::<Vec<_>>();
 let result=match args.as_slice(){
  [_,cmd,addr,mode] if cmd=="server"=>serve(addr,mode).map(|_|"SERVED"),
  [_,cmd,addr] if cmd=="client"=>client(addr),
  _=>Err("usage server HOST:PORT MODE | client HOST:PORT".into())
 };
 match result{Ok(s)=>println!("RESULT {s}"),Err(e)=>{eprintln!("ERROR {e}");std::process::exit(2)}}
}
#[cfg(test)]
mod tests{
 use super::*;
 #[test]fn keys_separated(){assert_ne!(noise_secret("server"),noise_secret("client"));assert_ne!(noise_public(noise_secret("server")),noise_public(noise_secret("attacker")));}
 #[test]fn signing_claim_not_truth(){let nonce=CHALLENGE;let x=message(&nonce,GENERATION,PIN,GOOD_UTC+3600);
 let sig=signer("server").sign(&x);assert!(signer("server").verifying_key().verify(&x,&sig).is_ok());}
 #[test]fn exact_domain(){let m=message(&CHALLENGE,GENERATION,PIN,GOOD_UTC);assert!(m.starts_with(DOMAIN));}
}
