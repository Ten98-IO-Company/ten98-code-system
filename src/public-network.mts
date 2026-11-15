import {BlockList,isIP} from 'node:net';
import {Resolver} from 'node:dns/promises';
import {normalizeClientAddress} from './client-address.mjs';

// Promoted from Discover's existing boundary; exclude special-purpose anycast as well as private space.
// IANA IPv4/IPv6 special-purpose registries, checked 2026-11-15. Cloud metadata and platform endpoints sit inside these
// ranges (169.254.169.254, 169.254.0.23, 100.100.100.200, fd00:ec2::254 and other ULAs), except Azure's platform
// (WireServer) address 168.63.129.16, which is in public space and is refused by name.
const reserved=new BlockList();
for(const[address,prefix]of [
 ['0.0.0.0',8],['10.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],
 ['169.254.0.0',16],['172.16.0.0',12],['192.0.0.0',24],['192.0.2.0',24],
 ['192.31.196.0',24],['192.52.193.0',24],['192.88.99.0',24],['192.168.0.0',16],
 ['192.175.48.0',24],['198.18.0.0',15],['198.51.100.0',24],['203.0.113.0',24],['224.0.0.0',3],
 ['168.63.129.16',32],
]as const)reserved.addSubnet(address,prefix,'ipv4');
for(const[address,prefix]of [['2001::',23],['2001:db8::',32],['2002::',16],['2620:4f:8000::',48],['3fff::',20]]as const)reserved.addSubnet(address,prefix,'ipv6');

export function addressKey(address:string):string{
 if(isIP(address)===4)return address;
 if(isIP(address)===6&&!address.includes('%')){
  try{return new URL(`http://[${address}]`).hostname.slice(1,-1);}catch{return '';}
 }
 return '';
}

export function publicNetworkAddress(address:string):boolean{
 const canonical=addressKey(address);if(!canonical)return false;
 if(isIP(canonical)===4)return !reserved.check(canonical,'ipv4');
 // Only global unicast 2000::/3, decided by the first 16-bit group of the canonical form. A form starting with '::'
 // has group 0, so unspecified, loopback, IPv4-mapped and IPv4-compatible addresses fail closed, as do translated
 // IPv4, ULA, link-local and multicast.
 const first=canonical.startsWith(':')?0:Number.parseInt(canonical.slice(0,canonical.indexOf(':')),16);
 return (first&0xe000)===0x2000&&!reserved.check(canonical,'ipv6');
}

/** Socket evidence permits IPv4-mapped IPv6 equivalence, without admitting mapped DNS targets. */
export function pinnedNetworkPeer(remote:unknown,pinned:string):boolean{
 const peer=normalizeClientAddress(remote);
 return peer!==null&&peer===normalizeClientAddress(pinned);
}

export type NetworkAddress={address:string;family:4|6};

/** Resolve both families completely. The caller must admit the entire answer set before connecting. */
export async function resolveNetworkHost(hostname:string,signal:AbortSignal):Promise<NetworkAddress[]>{
 signal.throwIfAborted();
 const literal=isIP(hostname);if(literal)return [{address:hostname,family:literal as 4|6}];
 const resolver=new Resolver({timeout:5000,tries:1});
 const cancel=()=>resolver.cancel();signal.addEventListener('abort',cancel,{once:true});
 try{
  signal.throwIfAborted();
  const values=await Promise.allSettled([resolver.resolve4(hostname),resolver.resolve6(hostname)]);
  signal.throwIfAborted();
  const result:NetworkAddress[]=[];
  for(const[index,value]of values.entries()){
   if(value.status==='rejected'){if(value.reason?.code!=='ENODATA')throw new Error('Network host unavailable.');continue;}
   for(const address of value.value)result.push({address,family:index===0?4:6});
  }
  return result;
 }finally{signal.removeEventListener('abort',cancel);resolver.cancel();}
}

// Public recursive resolvers (Cloudflare, then Google; IPv4, then IPv6) for ownership proofs, so a split-horizon system
// resolver can never answer for an internal zone.
const ownershipDnsServers=Object.freeze(['1.1.1.1','8.8.8.8','2606:4700:4700::1111','2001:4860:4860::8888']);
const txtLimits=Object.freeze({tryMs:3000,deadlineMs:5000,records:64,chunks:256,bytes:65536});

export type OwnershipTxtOptions={
 /** Resolver addresses, each an IP with an optional port. Defaults to Cloudflare and Google public DNS. Override only
  * with resolvers that answer from the public DNS, never from an internal view. */
 servers?:readonly string[];
 signal?:AbortSignal;
};

const txtLimit=()=>Object.assign(new Error('The TXT answer exceeds its bounds.'),{code:'ETXTLIMIT'});

/** TXT records for an ownership proof, from pinned public resolvers rather than the system resolver. One try per server,
 * at most 5 seconds, 64 records, 256 strings per record and 64 KiB in all; a larger answer rejects with code ETXTLIMIT,
 * the deadline with ETIMEOUT. DNS errors keep their codes (ENODATA, ENOTFOUND). An abort rejects with the signal's reason. */
export async function resolveOwnershipTxt(name:string,options:OwnershipTxtOptions={}):Promise<string[][]>{
 const{servers=ownershipDnsServers,signal}=options;
 if(typeof name!=='string'||!name||name.length>253||!Array.isArray(servers)||!servers.length)throw new TypeError('A DNS name and at least one resolver are required.');
 signal?.throwIfAborted();
 const resolver=new Resolver({timeout:txtLimits.tryMs,tries:1});
 resolver.setServers(servers);
 let timer:ReturnType<typeof setTimeout>|undefined;
 const cancel=()=>resolver.cancel();signal?.addEventListener('abort',cancel,{once:true});
 try{
  let records:string[][];
  try{
   records=await Promise.race([resolver.resolveTxt(name),new Promise<never>((_,reject)=>{
    timer=setTimeout(()=>reject(Object.assign(new Error('DNS lookup timed out.'),{code:'ETIMEOUT'})),txtLimits.deadlineMs);
   })]);
  }catch(error){signal?.throwIfAborted();throw error;}
  signal?.throwIfAborted();
  if(records.length>txtLimits.records)throw txtLimit();
  let bytes=0;
  for(const chunks of records){
   if(chunks.length>txtLimits.chunks)throw txtLimit();
   for(const chunk of chunks)bytes+=Buffer.byteLength(chunk);
  }
  if(bytes>txtLimits.bytes)throw txtLimit();
  return records;
 }finally{clearTimeout(timer);signal?.removeEventListener('abort',cancel);resolver.cancel();}
}
