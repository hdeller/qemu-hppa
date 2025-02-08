hppa_ss = ss.source_set()
hppa_ss.add(when: 'CONFIG_HPPA_B160L', if_true: files('machine.c'))
hppa_ss.add(when: 'CONFIG_NS87560_SUPERIO', if_true: files('ns87560_superio.c','ns-multi.c'))

hw_arch += {'hppa': hppa_ss}
