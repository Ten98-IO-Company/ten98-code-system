import assert from 'node:assert/strict';
import {test,mock,type TestContext} from 'node:test';
import {Resolver} from 'node:dns/promises';
import dgram from 'node:dgram';
import {once} from 'node:events';
import {addressKey,publicNetworkAddress,pinnedNetworkPeer,resolveNetworkHost,resolveOwnershipTxt} from '../public-network.mjs';

test('public targets retain Discover special-purpose exclusions and ordinary global unicast',()=>{
 for(const address of ['0.0.0.0','10.1.2.3','127.0.0.1','100.64.0.1','169.254.169.254','172.16.0.1','192.0.0.9','192.0.2.1','192.31.196.1','192.52.193.1','192.88.99.2','192.168.1.1','192.175.48.1','198.19.0.1','198.51.100.1','203.0.113.1','224.0.0.1','255.255.255.255','::','::1','::ffff:1.1.1.1','64:ff9b::101:101','2001:1::1','2001:2::1','2001:20::1','2001:db8::1','2002:101:101::1','2620:4f:8000::1','3fff::1','5f00::1','fc00::1','fe80::1','ff02::1','fe80::1%eth0','not-address','0127.0.0.1'])assert.equal(publicNetworkAddress(address),false,address);
 for(const address of ['1.1.1.1','8.8.8.8','2606:4700:4700::1111','2001:4860:4860::8888'])assert.equal(publicNetworkAddress(address),true,address);
 assert.equal(addressKey('fe80::1%eth0'),'');assert.equal(addressKey('2001:4860:4860:0:0:0:0:8888'),'2001:4860:4860::8888');
});

// Every textual form an address can take. isIP accepts only dotted-decimal IPv4, so integer, octal and hex spellings
// have no canonical key and fail closed even when they denote a public address.
test('global unicast is exactly 2000::/3 outside the reserved ranges, in every textual form',()=>{
 const accepted=['2000::1','2606:4700:4700::1111','2606:4700:4700:0:0:0:0:1111','2606:4700:4700:0000:0000:0000:0000:1111','2606:4700:4700::1111'.toUpperCase(),
  '2606:4700:4700:0::1111','2001:4860:4860::8888','2001:200::1','2400:cb00:2048:1::c629:d7a2','3fff:1000::1','3ffe::1','1.1.1.1','8.8.8.8','168.63.129.15','168.63.129.17'];
 const refused=[
  // Outside 2000::/3 although the first character is 2 or 3.
  '2::1','20::1','200::1','2ff::1','3::1','30::1','300::1','3ff::1','3ff:ffff::1','0002::1','0200:0:0:0:0:0:0:1','3FF::1','2:0:0:0:0:0:0:1','1fff:ffff::1','4000::1',
  // Reserved ranges inside 2000::/3.
  '2001::1','2001:1ff::1','2001:db8::1','2001:DB8:0:0:0:0:0:1','2002::1','2620:4f:8000::1','3fff::1','3fff:fff:ffff::1',
  // Zone ids and brackets.
  '2606:4700:4700::1111%eth0','2606:4700:4700::1111%1','[2606:4700:4700::1111]',
  // IPv4-mapped (dotted and hex), IPv4-compatible and translated forms of a public address.
  '::ffff:1.1.1.1','::FFFF:1.1.1.1','::ffff:101:101','0:0:0:0:0:ffff:101:101','0:0:0:0:0:FFFF:1.1.1.1','::ffff:0:1.1.1.1',
  '::1.1.1.1','::101:101','0:0:0:0:0:0:101:101','64:ff9b::1.1.1.1','64:ff9b::101:101','64:ff9b:1::101:101',
  // Integer, octal, hex and shortened IPv4 spellings, and padding.
  '16843009','0x01010101','01.1.1.1','001.001.001.001','0x1.0x1.0x1.0x1','1.1.1','1.1','0127.0.0.1','127.1','2130706433','0x7f000001',' 1.1.1.1','1.1.1.1 ','',
 ];
 for(const address of accepted)assert.equal(publicNetworkAddress(address),true,address);
 for(const address of refused)assert.equal(publicNetworkAddress(address),false,address);
});

test('cloud metadata and platform addresses are refused',()=>{
 // AWS, Azure, GCP, Oracle, DigitalOcean, Hetzner and OpenStack metadata; AWS DNS, time and ECS task metadata; Tencent;
 // Scaleway; Alibaba metadata; Azure's platform (WireServer) address; Oracle's legacy metadata; and the IPv6 metadata ULAs
 // of AWS, GCP, Oracle, Akamai Linode, Scaleway and Fly.io.
 for(const address of ['169.254.169.254','169.254.169.253','169.254.169.123','169.254.170.2','169.254.0.23','169.254.42.42','100.100.100.200',
  '168.63.129.16','::ffff:168.63.129.16','::ffff:a83f:8110','192.0.0.192','fd00:ec2::254','fd00:ec2::253','fd20:ce::254','fd00:c1::a9fe:a9fe',
  'fd00:a9fe:a9fe::1','fd00:42::42','fdaa::3'])assert.equal(publicNetworkAddress(address),false,address);
});

test('pinned peers accept mapped socket evidence but never invalid or mismatched endpoints',()=>{
 for(const[peer,pinned]of [['1.1.1.1','1.1.1.1'],['::ffff:1.1.1.1','1.1.1.1'],['::ffff:101:101','1.1.1.1'],['::FFFF:1.1.1.1','1.1.1.1'],['2606:4700:4700:0:0:0:0:1111','2606:4700:4700::1111']])assert.equal(pinnedNetworkPeer(peer,pinned),true);
 for(const[peer,pinned]of [['8.8.8.8','1.1.1.1'],['::ffff:8.8.8.8','1.1.1.1'],['2606:4700:4700::1111%eth0','2606:4700:4700::1111'],['[2606:4700:4700::1111]','2606:4700:4700::1111'],[' 1.1.1.1','1.1.1.1'],['','1.1.1.1'],[undefined,'1.1.1.1'],['not-address','not-address']])assert.equal(pinnedNetworkPeer(peer,pinned!),false);
});

test('resolution retains the complete answer set for caller admission and always cleans up',async()=>{
 const seen:string[]=[];
 const a=mock.method(Resolver.prototype,'resolve4',async(host:string)=>{seen.push(host);return ['1.1.1.1','10.0.0.1'];});
 const aaaa=mock.method(Resolver.prototype,'resolve6',async()=>['2606:4700:4700::1111']);
 const cancel=mock.method(Resolver.prototype,'cancel',()=>{});
 try{
  assert.deepEqual(await resolveNetworkHost('example.com',new AbortController().signal),[{address:'1.1.1.1',family:4},{address:'10.0.0.1',family:4},{address:'2606:4700:4700::1111',family:6}]);
  assert.deepEqual(seen,['example.com']);assert.equal(cancel.mock.callCount(),1);
 }finally{a.mock.restore();aaaa.mock.restore();cancel.mock.restore();}
});

test('a missing family is allowed but a partial DNS failure never becomes usable evidence',async()=>{
 const a=mock.method(Resolver.prototype,'resolve4',async()=>['1.1.1.1']);
 const aaaa=mock.method(Resolver.prototype,'resolve6',async()=>{throw Object.assign(new Error('no records'),{code:'ENODATA'});});
 const cancel=mock.method(Resolver.prototype,'cancel',()=>{});
 try{
  assert.deepEqual(await resolveNetworkHost('example.com',new AbortController().signal),[{address:'1.1.1.1',family:4}]);
  aaaa.mock.mockImplementation(async()=>{throw Object.assign(new Error('private provider detail'),{code:'ETIMEOUT'});});
  await assert.rejects(resolveNetworkHost('example.com',new AbortController().signal),{message:'Network host unavailable.'});
  assert.equal(cancel.mock.callCount(),2);
 }finally{a.mock.restore();aaaa.mock.restore();cancel.mock.restore();}
});

test('abort cancels pending resolution and pre-abort never resolves even literal targets',async()=>{
 const controller=new AbortController();let rejectPending:(error:Error)=>void=()=>{};
 const a=mock.method(Resolver.prototype,'resolve4',()=>new Promise<string[]>((_,reject)=>{rejectPending=reject;}));
 const aaaa=mock.method(Resolver.prototype,'resolve6',async()=>[]);
 const cancel=mock.method(Resolver.prototype,'cancel',()=>rejectPending(new Error('cancelled')));
 try{
  const pending=resolveNetworkHost('example.com',controller.signal);controller.abort();await assert.rejects(pending,{name:'AbortError'});
  assert.equal(cancel.mock.callCount(),2);assert.equal(a.mock.callCount(),1);
  await assert.rejects(resolveNetworkHost('1.1.1.1',controller.signal),{name:'AbortError'});assert.equal(a.mock.callCount(),1);
  assert.deepEqual(await resolveNetworkHost('1.1.1.1',new AbortController().signal),[{address:'1.1.1.1',family:4}]);assert.equal(a.mock.callCount(),1);
 }finally{a.mock.restore();aaaa.mock.restore();cancel.mock.restore();}
});

// A UDP DNS server on loopback that answers TXT queries from a table: records, NXDOMAIN, or no reply at all.
type StubAnswer=string[][]|'nxdomain'|'silent';
async function dnsStub(t:TestContext,answers:Record<string,StubAnswer>){
 const socket=dgram.createSocket('udp4'),queries:string[]=[];
 socket.on('message',(query,peer)=>{
  const labels:string[]=[];let offset=12;
  while(query[offset]){labels.push(query.subarray(offset+1,offset+1+query[offset]!).toString('latin1'));offset+=1+query[offset]!;}
  const question=query.subarray(12,offset+5),name=labels.join('.').toLowerCase();queries.push(name);
  const answer=answers[name]??[];if(answer==='silent')return;
  const records=answer==='nxdomain'?[]:answer;
  const header=Buffer.alloc(12);query.copy(header,0,0,2);
  header.writeUInt16BE(answer==='nxdomain'?0x8183:0x8180,2);header.writeUInt16BE(1,4);header.writeUInt16BE(records.length,6);
  const rdata=records.map(chunks=>Buffer.concat(chunks.flatMap(chunk=>[Buffer.from([Buffer.byteLength(chunk)]),Buffer.from(chunk)])));
  const resource=rdata.map(data=>{const fixed=Buffer.alloc(12);fixed.writeUInt16BE(0xc00c,0);fixed.writeUInt16BE(16,2);fixed.writeUInt16BE(1,4);fixed.writeUInt32BE(60,6);fixed.writeUInt16BE(data.length,10);return Buffer.concat([fixed,data]);});
  socket.send(Buffer.concat([header,question,...resource]),peer.port,peer.address);
 });
 socket.bind(0,'127.0.0.1');await once(socket,'listening');
 t.after(()=>socket.close());
 return {server:`127.0.0.1:${socket.address().port}`,queries};
}

test('ownership TXT lookups ask only the configured servers and keep DNS error codes',async t=>{
 const stub=await dnsStub(t,{'_proof.example.com':[['ten98-proof=abc'],['split ','record']],'_absent.example.com':'nxdomain','_empty.example.com':[]});
 assert.deepEqual(await resolveOwnershipTxt('_proof.example.com',{servers:[stub.server]}),[['ten98-proof=abc'],['split ','record']]);
 await assert.rejects(resolveOwnershipTxt('_absent.example.com',{servers:[stub.server]}),{code:'ENOTFOUND'});
 await assert.rejects(resolveOwnershipTxt('_empty.example.com',{servers:[stub.server]}),{code:'ENODATA'});
 assert.deepEqual(stub.queries,['_proof.example.com','_absent.example.com','_empty.example.com']);
});

test('ownership TXT lookups default to pinned public resolvers, never the system resolver',async()=>{
 let servers:string[]=[];
 const txt=mock.method(Resolver.prototype,'resolveTxt',async function(this:Resolver){servers=this.getServers();return [['ok']];});
 try{
  assert.deepEqual(await resolveOwnershipTxt('_proof.example.com'),[['ok']]);
  assert.deepEqual(servers,['1.1.1.1','8.8.8.8','2606:4700:4700::1111','2001:4860:4860::8888']);
  assert.deepEqual(await resolveOwnershipTxt('_proof.example.com',{servers:['192.0.2.53','[2001:db8::53]:5353']}),[['ok']]);
  assert.deepEqual(servers,['192.0.2.53','[2001:db8::53]:5353']);
 }finally{txt.mock.restore();}
 for(const options of [{servers:[]},{servers:'1.1.1.1' as unknown as string[]}])await assert.rejects(resolveOwnershipTxt('_proof.example.com',options),TypeError);
 await assert.rejects(resolveOwnershipTxt('_proof.example.com',{servers:['resolver.example']}),{code:'ERR_INVALID_IP_ADDRESS'});
 for(const name of ['',`${'a'.repeat(254)}`,7 as unknown as string])await assert.rejects(resolveOwnershipTxt(name),TypeError);
});

test('ownership TXT answers are bounded in record count, strings and bytes',async t=>{
 const many=Array.from({length:65},(_,index)=>[`r${index}`]);
 const stub=await dnsStub(t,{'_most.example.com':many.slice(0,64),'_many.example.com':many});
 assert.equal((await resolveOwnershipTxt('_most.example.com',{servers:[stub.server]})).length,64);
 await assert.rejects(resolveOwnershipTxt('_many.example.com',{servers:[stub.server]}),{code:'ETXTLIMIT'});
 const answers:string[][][]=[[Array(256).fill('a')],[Array(257).fill('a')],[['a'.repeat(32768)],['b'.repeat(32768)]],[['a'.repeat(32768)],['b'.repeat(32769)]]];
 const txt=mock.method(Resolver.prototype,'resolveTxt',async()=>answers.shift()!);
 try{
  assert.equal((await resolveOwnershipTxt('_proof.example.com'))[0]!.length,256);
  await assert.rejects(resolveOwnershipTxt('_proof.example.com'),{code:'ETXTLIMIT'});
  assert.equal((await resolveOwnershipTxt('_proof.example.com')).length,2);
  await assert.rejects(resolveOwnershipTxt('_proof.example.com'),{code:'ETXTLIMIT'});
 }finally{txt.mock.restore();}
});

test('ownership TXT lookups stop at the deadline or on abort and always cancel',{timeout:20000},async t=>{
 const stub=await dnsStub(t,{'_slow.example.com':'silent'});
 const controller=new AbortController();
 const pending=resolveOwnershipTxt('_slow.example.com',{servers:[stub.server],signal:controller.signal});
 const started=Date.now();setTimeout(()=>controller.abort(),50);
 await assert.rejects(pending,{name:'AbortError'});
 // The abort cancels the query rather than waiting out the resolver's own 3-second try.
 assert.ok(Date.now()-started<2500,'abort settles promptly');
 await assert.rejects(resolveOwnershipTxt('_slow.example.com',{servers:[stub.server],signal:controller.signal}),{name:'AbortError'});
 assert.deepEqual(stub.queries,['_slow.example.com']);
 t.mock.timers.enable({apis:['setTimeout']});
 const txt=t.mock.method(Resolver.prototype,'resolveTxt',()=>new Promise<string[][]>(()=>{}));
 const cancel=t.mock.method(Resolver.prototype,'cancel',()=>{});
 let settled:unknown;
 const late=resolveOwnershipTxt('_slow.example.com').then(()=>'resolved',(error:{code?:string})=>error.code);late.then(value=>{settled=value;});
 t.mock.timers.tick(4999);await new Promise(setImmediate);assert.equal(settled,undefined);
 t.mock.timers.tick(1);await new Promise(setImmediate);
 assert.equal(settled,'ETIMEOUT');
 assert.equal(txt.mock.callCount(),1);assert.equal(cancel.mock.callCount(),1);
});
