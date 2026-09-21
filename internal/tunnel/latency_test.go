package tunnel

import (
	"context"
	"testing"
	"time"
)

// A write must be acknowledged within a round trip plus the delayed-ACK
// timer, not seconds: the stall detector and the user's latency both depend
// on it.
func TestFirstWriteAckedPromptly(t *testing.T) {
	env := startEnv(t)
	c := resilientClient(t, env.server, "")
	for i := 0; i < 3; i++ {
		st, err := c.OpenStream(context.Background(), addrOf(t, env.echo))
		if err != nil {
			t.Fatal(err)
		}
		acker := st.(interface{ Acked() uint64 })
		t0 := time.Now()
		st.Write(make([]byte, 16<<10))
		for acker.Acked() < 16<<10 {
			if time.Since(t0) > 3*time.Second {
				t.Fatalf("stream %d: 16 KB not acknowledged after %v", i, time.Since(t0))
			}
			time.Sleep(time.Millisecond)
		}
		t.Logf("stream %d acknowledged in %v", i, time.Since(t0))
		if d := time.Since(t0); d > 500*time.Millisecond {
			t.Errorf("stream %d: acknowledgement took %v", i, d)
		}
		st.Close()
	}
}
