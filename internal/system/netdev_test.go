package system

import "testing"

func TestParseNetDev(t *testing.T) {
	in := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 9999999     100    0    0    0     0          0         0  9999999     100    0    0    0     0       0          0
  eth0: 1000      10    0    0    0     0          0         0     2000      20    0    0    0     0       0          0
docker0: 500     5    0    0    0     0          0         0     700      7    0    0    0     0       0          0
vethab12: 50     5    0    0    0     0          0         0     70      7    0    0    0     0       0          0
  ens4: 1      1    0    0    0     0          0         0     2      1    0    0    0     0       0          0
`
	rx, tx, ok := ParseNetDev(in)
	if !ok || rx != 1001 || tx != 2002 {
		t.Fatalf("rx %d tx %d", rx, tx)
	}
}
