package gatewaybench

import (
	"runtime"
	"runtime/metrics"
	"time"
)

type resourceSample struct {
	at         time.Time
	mem        runtime.MemStats
	userMS     float64
	systemMS   float64
	peakRSS    int64
	gcCPU      float64
	assist     float64
	stopping   *metrics.Float64Histogram
	totalPause *metrics.Float64Histogram
}

type ResourceWindow struct {
	WindowMS          float64         `json:"window_ms"`
	UserCPUMS         float64         `json:"process_user_cpu_ms"`
	SystemCPUMS       float64         `json:"process_system_cpu_ms"`
	AverageCPUCores   float64         `json:"average_process_cpu_cores"`
	PeakRSS           int64           `json:"peak_rss_bytes_since_process_start"`
	HeapBefore        uint64          `json:"heap_alloc_before_bytes"`
	HeapAfter         uint64          `json:"heap_alloc_after_bytes"`
	HeapSysBefore     uint64          `json:"heap_sys_before_bytes"`
	HeapSysAfter      uint64          `json:"heap_sys_after_bytes"`
	AllocatedBytes    uint64          `json:"allocated_bytes"`
	Allocations       uint64          `json:"allocations"`
	GCCycles          uint32          `json:"gc_cycles"`
	GCPauseMS         float64         `json:"gc_pause_total_ms"`
	EstimatedGCCPUMS  float64         `json:"estimated_gc_cpu_ms"`
	EstimatedAssistMS float64         `json:"estimated_gc_assist_cpu_ms"`
	GCStopping        *PauseHistogram `json:"gc_stopping,omitempty"`
	GCTotalPause      *PauseHistogram `json:"gc_total_pause,omitempty"`
}

func sampleResources() (resourceSample, error) {
	v := resourceSample{at: time.Now()}
	runtime.ReadMemStats(&v.mem)
	samples := []metrics.Sample{{Name: "/cpu/classes/gc/total:cpu-seconds"}, {Name: "/cpu/classes/gc/mark/assist:cpu-seconds"}, {Name: "/sched/pauses/stopping/gc:seconds"}, {Name: "/sched/pauses/total/gc:seconds"}}
	metrics.Read(samples)
	if samples[0].Value.Kind() != metrics.KindFloat64 || samples[1].Value.Kind() != metrics.KindFloat64 || samples[2].Value.Kind() != metrics.KindFloat64Histogram || samples[3].Value.Kind() != metrics.KindFloat64Histogram {
		return v, errUnsupportedResources
	}
	v.gcCPU, v.assist = samples[0].Value.Float64(), samples[1].Value.Float64()
	v.stopping, v.totalPause = cloneHistogram(samples[2].Value.Float64Histogram()), cloneHistogram(samples[3].Value.Float64Histogram())
	var err error
	v.userMS, v.systemMS, v.peakRSS, err = processResources()
	return v, err
}

func resourcesBetween(a, b resourceSample) ResourceWindow {
	window := float64(b.at.Sub(a.at)) / float64(time.Millisecond)
	user, system := b.userMS-a.userMS, b.systemMS-a.systemMS
	return ResourceWindow{WindowMS: window, UserCPUMS: user, SystemCPUMS: system, AverageCPUCores: (user + system) / window, PeakRSS: b.peakRSS,
		HeapBefore: a.mem.HeapAlloc, HeapAfter: b.mem.HeapAlloc, HeapSysBefore: a.mem.HeapSys, HeapSysAfter: b.mem.HeapSys,
		AllocatedBytes: b.mem.TotalAlloc - a.mem.TotalAlloc, Allocations: b.mem.Mallocs - a.mem.Mallocs, GCCycles: b.mem.NumGC - a.mem.NumGC,
		GCPauseMS: float64(b.mem.PauseTotalNs-a.mem.PauseTotalNs) / 1e6, EstimatedGCCPUMS: (b.gcCPU - a.gcCPU) * 1000, EstimatedAssistMS: (b.assist - a.assist) * 1000,
		GCStopping: pauseDelta(a.stopping, b.stopping), GCTotalPause: pauseDelta(a.totalPause, b.totalPause)}
}
