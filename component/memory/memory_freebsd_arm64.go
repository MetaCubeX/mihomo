package memory

const sizeOfKinfoProc = 0x440

type Timeval struct {
	Sec  int64
	Usec int64
}

type Rusage struct {
	Utime    Timeval
	Stime    Timeval
	Maxrss   int64
	Ixrss    int64
	Idrss    int64
	Isrss    int64
	Minflt   int64
	Majflt   int64
	Nswap    int64
	Inblock  int64
	Oublock  int64
	Msgsnd   int64
	Msgrcv   int64
	Nsignals int64
	Nvcsw    int64
	Nivcsw   int64
}

type KinfoProc struct {
	Structsize     int32
	Layout         int32
	Args           int64 /* pargs */
	Paddr          int64 /* proc */
	Addr           int64 /* user */
	Tracep         int64 /* vnode */
	Textvp         int64 /* vnode */
	Fd             int64 /* filedesc */
	Vmspace        int64 /* vmspace */
	Wchan          int64
	Pid            int32
	Ppid           int32
	Pgid           int32
	Tpgid          int32
	Sid            int32
	Tsid           int32
	Jobc           int16
	Spare_short1   int16
	Tdev_freebsd11 uint32
	Siglist        [16]byte /* sigset */
	Sigmask        [16]byte /* sigset */
	Sigignore      [16]byte /* sigset */
	Sigcatch       [16]byte /* sigset */
	Uid            uint32
	Ruid           uint32
	Svuid          uint32
	Rgid           uint32
	Svgid          uint32
	Ngroups        int16
	Spare_short2   int16
	Groups         [16]uint32
	Size           uint64
	Rssize         int64
	Swrss          int64
	Tsize          int64
	Dsize          int64
	Ssize          int64
	Xstat          uint16
	Acflag         uint16
	Pctcpu         uint32
	Estcpu         uint32
	Slptime        uint32
	Swtime         uint32
	Cow            uint32
	Runtime        uint64
	Start          Timeval
	Childtime      Timeval
	Flag           int64
	Kiflag         int64
	Traceflag      int32
	Stat           uint8
	Nice           int8
	Lock           uint8
	Rqindex        uint8
	Oncpu_old      uint8
	Lastcpu_old    uint8
	Tdname         [17]uint8
	Wmesg          [9]uint8
	Login          [18]uint8
	Lockname       [9]uint8
	Comm           [20]int8 // changed from uint8 by hand
	Emul           [17]uint8
	Loginclass     [18]uint8
	Moretdname     [4]uint8
	Sparestrings   [46]uint8
	Spareints      [2]int32
	Tdev           uint64
	Oncpu          int32
	Lastcpu        int32
	Tracer         int32
	Flag2          int32
	Fibnum         int32
	Cr_flags       uint32
	Jid            int32
	Numthreads     int32
	Tid            int32
	Pri            Priority
	Rusage         Rusage
	Rusage_ch      Rusage
	Pcb            int64 /* pcb */
	Kstack         int64
	Udata          int64
	Tdaddr         int64 /* thread */
	Pd             int64 /* pwddesc, not accurate */
	Spareptrs      [5]int64
	Sparelongs     [12]int64
	Sflag          int64
	Tdflags        int64
}

type Priority struct {
	Class  uint8
	Level  uint8
	Native uint8
	User   uint8
}
