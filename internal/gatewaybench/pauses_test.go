package gatewaybench

import (
	"encoding/json"
	"math"
	"runtime/metrics"
	"testing"
)

func TestPauseHistogramSnapshotAndDelta(t *testing.T) {
	before := &metrics.Float64Histogram{Buckets: []float64{math.Inf(-1), 0, .001, .002, math.Inf(1)}, Counts: []uint64{0, 1, 2, 0}}
	after := cloneHistogram(before)
	after.Counts[1] += 2
	after.Counts[2] += 3
	h := pauseDelta(before, after)
	if before.Counts[1] != 1 || h == nil || h.Count != 5 || h.TotalLowerMS != 3 || h.TotalUpperMS == nil || *h.TotalUpperMS != 8 || len(h.Buckets) != 2 {
		t.Fatal("snapshot alias or incorrect bucket bounds", h)
	}
	if h.Buckets[0].LowerMS != 0 || *h.Buckets[0].UpperMS != 1 || h.Buckets[0].Count != 2 || h.Buckets[1].LowerMS != 1 || *h.Buckets[1].UpperMS != 2 {
		t.Fatal("runtime histogram precision lost", h)
	}
	// Runtime histograms can include an infinite terminal bucket. JSON must
	// retain an unknown upper bound rather than invent a finite duration.
	after.Counts[3]++
	h = pauseDelta(before, after)
	if h.Count != 6 || h.TotalLowerMS != 5 || h.TotalUpperMS != nil || h.Buckets[2].UpperMS != nil {
		t.Fatal("infinite upper bound not preserved", h)
	}
	if _, err := json.Marshal(h); err != nil {
		t.Fatal("histogram is not JSON-safe", err)
	}
	zero := pauseDelta(before, before)
	if zero == nil || zero.Count != 0 || zero.TotalLowerMS != 0 || zero.TotalUpperMS == nil || *zero.TotalUpperMS != 0 || zero.Buckets == nil {
		t.Fatal("zero pauses must remain a measured zero", zero)
	}
	after.Buckets[1] = .0001
	if before.Buckets[1] != 0 || pauseDelta(before, after) != nil {
		t.Fatal("changed buckets or aliased snapshot accepted")
	}
	reset := cloneHistogram(before)
	reset.Counts[2]--
	if pauseDelta(before, reset) != nil || pauseDelta(nil, before) != nil || pauseDelta(before, &metrics.Float64Histogram{}) != nil {
		t.Fatal("missing or reset counters must remain unknown")
	}
}
