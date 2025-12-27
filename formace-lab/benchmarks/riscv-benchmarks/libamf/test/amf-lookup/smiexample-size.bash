#include "_tempdir.bash"

LOOKUP_STRING="smiexample/size"

cat > config_string <<EOF
platform {
  vendor ucb;
  arch rocket;
};
plic {
  priority 0x40000000;
  pending 0x40001000;
  ndevs 2;
};
rtc {
  addr 0x2000;
};
ram {
  0 {
    addr 0x80000000;
    size 0x80000000;
  };
};
smiexample {
  addr 0x48000000;
  size 0x400;
};
core {
  0 {
    0 {
      isa rv64imafd;
      timecmp 0x2008;
      ipi 0x44000000;
      plic {
        m {
         ie 0x40002000;
         thresh 0x40200000;
         claim 0x40200004;
        };
        s {
         ie 0x40002080;
         thresh 0x40201000;
         claim 0x40201004;
        };
      };
    };
  };
};
EOF

cat >output.gold <<EOF
0x400
EOF

#include "_harness.bash"
