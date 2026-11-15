import assert from 'node:assert/strict';
import {test,mock} from 'node:test';
import {Resolver} from 'node:dns/promises';
import {addressKey,publicNetworkAddress,pinnedNetworkPeer,resolveNetworkHost} from '../public-network.mjs';

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
