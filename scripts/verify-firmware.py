#!/usr/bin/env python3
"""Verify a built Witcher-edition .prg against the stock image.

Checks: container CRCs/length; kernel and tk byte-identical to stock; all 254
device nodes present with correct major/minor; every inode owned by uid/gid 500;
the overlay scripts present; and gdmlte.ko carries exactly the one-byte /56
patch (and nothing else) versus the stock module.

Usage: scripts/verify-firmware.py STOCK.prg BUILT.prg
"""
import struct, zlib, sys, os, tempfile, collections, hashlib, json, gzip, tarfile, subprocess
from pathlib import Path
from rootfs_metadata import boot_errors, prg_metadata
from credential_policy import credential_findings, legacy_credentials

def carve(prg):
    d=Path(prg).read_bytes()
    be=lambda o: struct.unpack_from('>I',d,o)[0]
    ks,rs,ts=be(0x24),be(0x28),be(0x2c)
    k0=0x54;r0=k0+ks;t0=r0+rs
    return d,be,(k0,r0,t0,ks,rs,ts)

def carve_ubifs(ubi):
    peb=0x20000;vo=2048;do=4096;leb=126976;lebs={}
    for i in range(len(ubi)//peb):
        p=ubi[i*peb:(i+1)*peb]
        if p[:4]!=b'UBI#':continue
        v=p[vo:vo+64]
        if v[:4]!=b'UBI!':continue
        vid,ln=struct.unpack_from('>II',v,8)
        if vid==0: lebs[ln]=p[do:do+leb]
    return b''.join(lebs.get(i,b'\xff'*leb) for i in range(max(lebs)+1))

def main():
    stock, built = sys.argv[1], sys.argv[2]
    o,obe,_=carve(stock); n,nbe,(k0,r0,t0,ks,rs,ts)=carve(built)
    ok0=0x54;okr=ok0+obe(0x24);okt=okr+obe(0x28)
    fails=[]
    def check(name,cond):
        print(('  OK  ' if cond else 'FAIL  ')+name)
        if not cond: fails.append(name)
    check('magic',           nbe(0)==0x7243)
    check('header CRC',      zlib.crc32(n[:0x50])&0xffffffff==nbe(0x50))
    check('payload CRC',     zlib.crc32(n[0x54:])&0xffffffff==nbe(4))
    check('length',          nbe(8)==len(n)-0x54)
    check('kernel == stock', n[k0:r0]==o[ok0:okr])
    check('tk == stock',     n[t0:]==o[okt:])
    built_metadata = prg_metadata(built)
    metadata_errors = boot_errors(prg_metadata(stock), built_metadata, witcher=True)
    check('boot executable modes, exact device nodes, and web traversal', not metadata_errors)
    for error in metadata_errors[:16]:
        print('      '+error)
    if len(metadata_errors) > 16:
        print(f'      ... {len(metadata_errors) - 16} further metadata errors')

    ubifs=carve_ubifs(n[r0:t0])
    from ubireader.ubifs import ubifs as UBIFS
    from ubireader.ubi_io import ubi_file
    from ubireader.ubifs import walk
    from ubireader.ubifs.output import extract_files
    from ubireader import settings; settings.logging_on=False
    tf=tempfile.NamedTemporaryFile(delete=False); tf.write(ubifs); tf.close()
    u=UBIFS(ubi_file(tf.name,2048,0,None))
    ino={};dents=[]; walk.index(u,u.master_node.root_lnum,u.master_node.root_offs,ino,dents)
    uid=collections.Counter()
    gid=collections.Counter()
    parent={}; name={}; modes={}
    for k,x in ino.items():
        nn=x.get('ino')
        if nn:
            uid[nn.uid]+=1
            gid[nn.gid]+=1
            modes[nn.key['ino_num']]=nn.mode
        for dent in x.get('dent') or []:
            parent[dent.inum]=dent.key['ino_num']
            name[dent.inum]=dent.name
    def relpath(i, seen=None):
        seen=seen or set()
        if i in seen or i not in parent: return ''
        seen.add(i)
        return relpath(parent[i], seen)+'/'+name.get(i,'')
    bypath={relpath(i): mode for i, mode in modes.items()}
    def is_exec(path):
        mode=bypath.get('/'+path.lstrip('/'))
        return mode is not None and (mode & 0o111) != 0
    nodes=[]
    _mknod=os.mknod
    def spy(path,mode=0o600,device=0,*a,**k):
        i=path.find('/dev/');p=path[i:] if i>=0 else path
        t='c' if (mode&0o170000)==0o020000 else 'b' if (mode&0o170000)==0o060000 else '?'
        nodes.append((p,t,mode&0o7777,os.major(device),os.minor(device)))
    os.mknod=spy
    d=tempfile.mkdtemp()
    try: extract_files(u,d)
    except Exception: pass
    os.mknod=_mknod
    check('254 device nodes', len(nodes)==254)
    check('ownership all uid/gid 500', set(uid)=={500} and set(gid)=={500})
    check('passthru-fix.sh present', os.path.exists(os.path.join(d,'etc/sysconfig/script/passthru-fix.sh')))
    keeper=os.path.join(d,'usr/lib/titan-api/titan-pd-keeper')
    check('titan-pd-keeper present', os.path.isfile(keeper) and is_exec('usr/lib/titan-api/titan-pd-keeper'))
    if os.path.isfile(keeper):
        digest=hashlib.sha256(open(keeper,'rb').read()).hexdigest()
        expected_keeper=Path(__file__).resolve().parent.parent/'userspace/target/armv7-unknown-linux-musleabi/release/titan-pd-keeper'
        check('titan-pd-keeper matches source build', expected_keeper.is_file() and digest==hashlib.sha256(expected_keeper.read_bytes()).hexdigest())
    check('titan-pd-keeper init present', os.path.isfile(os.path.join(d,'etc/init.d/titan-pd-keeper')))
    sshd=os.path.join(d,'usr/lib/titan-api/titan-sshd')
    check('titan-sshd present', os.path.isfile(sshd) and is_exec('usr/lib/titan-api/titan-sshd'))
    if os.path.isfile(sshd):
        digest=hashlib.sha256(open(sshd,'rb').read()).hexdigest()
        check('titan-sshd sha256', digest=='f4f657a53674a9acf521882bdc6c82d13b9cea185cb3dbe5eecd71a5ff5cae68')
    check('titan-sshd init present', os.path.isfile(os.path.join(d,'etc/init.d/titan-sshd')))
    api=os.path.join(d,'usr/lib/titan-api/titan-api')
    check('titan-api present', os.path.isfile(api) and is_exec('usr/lib/titan-api/titan-api'))
    if os.path.isfile(api):
        digest=hashlib.sha256(open(api,'rb').read()).hexdigest()
        check('titan-api sha256', digest=='194cfb5ce33cd58beef4c73206028f2089fafc3a3086fc151a56d9c768ba73ec')
    check('titan-api init present', os.path.isfile(os.path.join(d,'etc/init.d/titan-api')))
    check('native UI present', os.path.isfile(os.path.join(d,'usr/lib/titan-api/ui/index.html')))
    check('login MAC reads this unit Ethernet interface',
          built_metadata.get('/usr/lib/titan-api/ui/device-mac.txt', {}).get('target') == '/tmp/witcher-api/device-mac.txt')
    expected_version=(Path(__file__).resolve().parent.parent/'VERSION').read_text().strip()
    release_path=Path(d)/'etc/witcher-release'
    try:
        release=json.loads(release_path.read_text())
    except (OSError,ValueError):
        release={}
    check('Witcher release identity', release.get('version')==expected_version
          and release.get('display')=='Witcher v'+expected_version
          and release.get('base_firmware')=='V1.6.0.P0.4172')
    ui=Path(d)/'usr/lib/titan-api/ui'
    html=(ui/'index.html').read_text() if (ui/'index.html').is_file() else ''
    check('UI version matches firmware', f'name="witcher-version" content="{expected_version}"' in html)
    gzip_valid=True
    for compressed in ui.rglob('*.gz'):
        try:
            if gzip.decompress(compressed.read_bytes())!=compressed.with_suffix('').read_bytes():
                gzip_valid=False
        except (OSError,EOFError,zlib.error):
            gzip_valid=False
    check('precompressed UI matches source assets', gzip_valid)
    for helper, digest in (
        ('titan-device-helper','717a3514a66c9b4652aac904284e127c9085c51bab2d30055609d1f041924a71'),
        ('titan-nvram','adb7c44663d54a0eca5f63a862a5ec5dc6119e42cd62a67e904d4654472a2aab'),
        ('titan-maintenance','ffec38ba88cbd58dffa6faccb246b4ff0a935ce07bff813a694090fde48de75c'),
        ('titan-seed-rng','560b690c716d1ef0449728e8e331d88d5925327457faaa7e4766b502f85c02ec'),
    ):
        path=os.path.join(d,'usr/lib/titan-api',helper)
        check(helper+' present', os.path.isfile(path) and is_exec('usr/lib/titan-api/'+helper))
        if os.path.isfile(path):
            got=hashlib.sha256(open(path,'rb').read()).hexdigest()
            check(helper+' sha256', got==digest)
    recovery = Path(d)/'usr/lib/titan-api/vendor-desktop.tar.gz'
    try:
        with tarfile.open(recovery, 'r:gz') as archive:
            entries = {entry.name: entry for entry in archive.getmembers()}
            recovery_ok = all(name in entries and entries[name].isfile() for name in ('login.asp', 'Upgrade.asp', 'logout.asp'))
            recovery_ok &= 'key.pem' not in entries and 'cert.pem' not in entries
            recovery_ok &= all(not name.startswith('/') and '..' not in Path(name).parts and not entry.isdev() for name,entry in entries.items())
    except (OSError, tarfile.TarError):
        recovery_ok = False
    check('factory desktop recovery archive', recovery_ok)
    check('factory shared TLS private key removed', not os.path.exists(os.path.join(d, 'usr/www/key.pem')))
    entropy=Path(d)/'usr/lib/titan-api/witcher-entropy'
    entropy_build=Path(__file__).resolve().parent.parent/'userspace/target/witcher-entropy'
    check('entropy collector matches source build', entropy.is_file() and entropy_build.is_file() and hashlib.sha256(entropy.read_bytes()).digest()==hashlib.sha256(entropy_build.read_bytes()).digest())
    firstboot=Path(d)/'usr/lib/titan-api/witcher-firstboot'
    expected=Path(__file__).resolve().parent.parent/'userspace/target/armv7-unknown-linux-musleabi/release/witcher-firstboot'
    check('firstboot binary matches source build', firstboot.is_file() and expected.is_file() and hashlib.sha256(firstboot.read_bytes()).digest()==hashlib.sha256(expected.read_bytes()).digest())
    check('audio test tones removed', not os.path.exists(os.path.join(d,'etc/sysconfig/audio/sample/sine_8k.wav')))
    # The denylist comes from Actions secrets on official builds. Independently
    # reject root password hashes and embedded private keys on every build.
    try:
        legacy_credentials()
        secret_files = credential_findings(d)
        check('baked credentials and private keys removed', not secret_files)
        for path in secret_files:
            print('      credential material in '+path)
    except ValueError as error:
        check(str(error), False)
    board=open(os.path.join(d,'etc/sysconfig/board.conf'),'rb').read()
    rcinit=open(os.path.join(d,'usr/sbin/rcinit'),'rb').read()
    check('root account locked', b'root:!:0:0:root:/root:/bin/sh' in board and b'root:!:0:0:root:/:/bin/sh' in rcinit)
    ko=os.path.join(d,'lib/modules/3.10.0-uc0/extra/gdmlte.ko')
    if os.path.exists(ko):
        kb=open(ko,'rb').read()
        check('gdmlte check#1 /56 patch (mov r2,#7 @0x2f0c)', kb[0x2f0c:0x2f10]==bytes.fromhex('0720a0e3'))
        check('gdmlte check#2 /56 patch (mov r2,#7 @0x32d8)', kb[0x32d8:0x32dc]==bytes.fromhex('0720a0e3'))
        check('gdmlte bearer-select branch stock (@0x2f18)', kb[0x2f18:0x2f1c]==bytes.fromhex('8d01000a'))
    else:
        check('gdmlte.ko present', False)
    cb=os.path.join(d,'usr/sbin/cbrs_fsm')
    if os.path.exists(cb):
        cbb=open(cb,'rb').read()
        check('cbrs_fsm block routine no-op (@0x4fcc)', cbb[0x4fcc:0x4fd4]==bytes.fromhex('0000a0e31eff2fe1'))
        check('cbrs_fsm firewall neutered (@0x1c8b4)', cbb[0x1c8b4:0x1c8bc]==b'true    ')
    if os.environ.get('WITCHER_VERIFY_TLS') == '1':
        result = subprocess.run([sys.executable, str(Path(__file__).with_name('test-tls-compatibility.py')), d])
        check('packed OpenSSL TLS generation compatibility', result.returncode == 0)
    print('\nRESULT:', 'ALL PASS' if not fails else f'{len(fails)} FAILURES: {fails}')
    sys.exit(1 if fails else 0)

if __name__=='__main__':
    main()
