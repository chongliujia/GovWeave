package gatewaybench

import (
	"math"
	"runtime/metrics"
	"slices"
)

// PauseBucket retains the runtime's histogram precision rather than inventing
// exact pause durations. Upper bounds are exclusive; nil denotes +Inf.
type PauseBucket struct {
	LowerMS float64  `json:"lower_ms"`
	UpperMS *float64 `json:"upper_ms"`
	Count   uint64   `json:"count"`
}

type PauseHistogram struct {
	Count        uint64        `json:"count"`
	TotalLowerMS float64       `json:"total_lower_ms"`
	TotalUpperMS *float64      `json:"total_upper_ms"`
	Buckets      []PauseBucket `json:"buckets"`
}

func cloneHistogram(h *metrics.Float64Histogram) *metrics.Float64Histogram {
	return &metrics.Float64Histogram{Buckets: slices.Clone(h.Buckets), Counts: slices.Clone(h.Counts)}
}

func pauseDelta(before, after *metrics.Float64Histogram) *PauseHistogram {
	if before == nil || after == nil || !slices.Equal(before.Buckets, after.Buckets) || len(before.Counts) != len(after.Counts) || len(after.Buckets) != len(after.Counts)+1 {
		return nil
	}
	h := &PauseHistogram{Buckets: []PauseBucket{}}
	upperSum := 0.0
	h.TotalUpperMS = &upperSum
	for i, end := range after.Counts {
		if end < before.Counts[i] {
			return nil
		}
		count := end - before.Counts[i]
		if count == 0 {
			continue
		}
		lower, upper := math.Max(0, after.Buckets[i]*1000), after.Buckets[i+1]*1000
		if math.IsNaN(lower) || math.IsInf(lower, 1) || math.IsNaN(upper) || upper < lower {
			return nil
		}
		bucket := PauseBucket{LowerMS: lower, Count: count}
		if !math.IsInf(upper, 1) {
			bucket.UpperMS = &upper
			upperSum += float64(count) * upper
		} else {
			h.TotalUpperMS = nil
		}
		h.Buckets = append(h.Buckets, bucket)
		h.Count += count
		h.TotalLowerMS += float64(count) * lower
	}
	return h
}
