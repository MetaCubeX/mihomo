import ctypes, fcntl, json, os, socket, struct, subprocess, sys

ADDR = '198.19.255.1'

def main():
    if os.geteuid() != 0:
        raise SystemExit('Administrator privileges required for isolated utun.')
    if ADDR in subprocess.check_output(['/sbin/ifconfig'], text=True):
        raise SystemExit('Test address already exists; refusing to proceed.')
    route = subprocess.check_output(['/sbin/route', '-n', 'get', 'default'], text=True)
    iface = next(line.split(':',1)[1].strip() for line in route.splitlines() if 'interface:' in line)
    if iface.startswith('utun') or iface == 'lo0':
        raise SystemExit('Default route is not physical; refusing to proceed.')
    physical_ip = subprocess.check_output(['/usr/sbin/ipconfig', 'getifaddr', iface], text=True).strip()
    tun = socket.socket(32, socket.SOCK_DGRAM, 2)
    name = None
    try:
        info = fcntl.ioctl(tun.fileno(), 0xc0644e03, struct.pack('I96s',0,b'com.apple.net.utun_control'))
        cid = struct.unpack('I96s',info)[0]
        sa = struct.pack('BBHII5I',32,32,2,cid,0,0,0,0,0,0)
        libc = ctypes.CDLL(None,use_errno=True)
        buf = ctypes.create_string_buffer(sa)
        if libc.connect(tun.fileno(),buf,len(sa)) != 0:
            raise OSError(ctypes.get_errno(),os.strerror(ctypes.get_errno()))
        name = tun.getsockopt(2,2,64).split(b'\0')[0].decode()
        subprocess.run(['/sbin/ifconfig',name,'inet',ADDR,ADDR,'netmask','255.255.255.252','up'],check=True)
        print(json.dumps({'interface':name,'physical_interface':iface,'test_address':ADDR,'physical_ip':physical_ip}),flush=True)
        env = dict(os.environ, MIHOMO_PROOF_TUN_FD=str(tun.fileno()), MIHOMO_PROOF_IFACE=iface, MIHOMO_PROOF_IP=physical_ip)
        if len(sys.argv) > 2 and sys.argv[2] == 'physical':
            env['MIHOMO_PROOF_CLIENT_IP'] = physical_ip
            print('CONTROL: original client uses physical interface IP', flush=True)
        result = subprocess.run([sys.argv[1],'-test.v','-test.run','^Test(TUNReplyCannotReenterOutbound|UDPForwardingAfterPortGuard)$','-test.timeout','8s'],env=env,pass_fds=(tun.fileno(),),timeout=12)
        return result.returncode
    finally:
        if name:
            subprocess.run(['/sbin/ifconfig',name,'inet',ADDR,'delete'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        tun.close()
        print('CLEANUP: removed test address and closed isolated utun; existing routes/config untouched',flush=True)

if __name__ == '__main__':
    raise SystemExit(main())
