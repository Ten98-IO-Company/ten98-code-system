import assert from 'node:assert/strict';
import {test,mock} from 'node:test';
import {Resolver} from 'node:dns/promises';
import {addressKey,publicNetworkAddress,pinnedNetworkPeer,resolveNetworkHost} from '../public-network.mjs';

test('public targets retain Discover special-purpose exclusions and ordinary global unicast',()=>{
 for(const address of ['0.0.0.0','10.1.2.3','127.0.0.1','100.64.0.1','169.254.169.254','172.16.0.1','192.0.0.9','192.0.2.1','192.31.196.1','192.52.193.1','192.88.99.2','192.168.1.1','192.175.48.1','198.19.0.1','198.51.100.1','203.0.113.1','224.0.0.1','255.255.255.255','::','::1','::ffff:1.1.1.1','64:ff9b::101:101','2001:1::1','2001:2::1','2001:20::1','2001:db8::1','2002:101:101::1','2620:4f:8000::1','3fff::1','5f00::1','fc00::1','fe80::1','ff02::1','fe80::1%eth0','not-address','0127.0.0.1'])assert.equal(publicNetworkAddress(address),false,address);
 for(const address of ['1.1.1.1','8.8.8.8','2606:4700:4700::1111','2001:4860:4860::8888'])assert.equal(publicNetworkAddress(address),true,address);
 assert.equal(addressKey('fe80::1%eth0'),'');assert.equal(addressKey('2001:4860:4860:0:0:0:0:8888'),'2001:4860:4860::8888');
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
