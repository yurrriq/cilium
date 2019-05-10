// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	namespace    = "operator"
	eniSubsystem = "eni"
)

var (
	registry                 *prometheus.Registry
	metricEniAllocateEniOps  *prometheus.CounterVec
	metricEniAllocateIpOps   *prometheus.CounterVec
	metricEniIPsAllocated    *prometheus.GaugeVec
	metricEniAvailable       prometheus.Gauge
	metricEniNodesAtCapacity prometheus.Gauge
	metricEniAwsApiDuration  *prometheus.HistogramVec
	metricEniResync          prometheus.Counter
)

func registerMetrics() {
	registry = prometheus.NewPedanticRegistry()
	mustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{Namespace: namespace}))

	metricEniIPsAllocated = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: eniSubsystem,
		Name:      "ips",
		Help:      "Number of IPs allocated",
	}, []string{"type"})
	mustRegister(metricEniIPsAllocated)

	metricEniAllocateIpOps = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: eniSubsystem,
		Name:      "allocation_ops",
		Help:      "Number of IP allocation operations",
	}, []string{"subnetId"})
	mustRegister(metricEniAllocateIpOps)

	metricEniAllocateEniOps = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: eniSubsystem,
		Name:      "interface_creation_ops",
		Help:      "Number of ENIs allocated",
	}, []string{"subnetId", "status"})
	mustRegister(metricEniAllocateEniOps)

	metricEniAvailable = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: eniSubsystem,
		Name:      "available",
		Help:      "Number of ENIs with addresses available",
	})
	mustRegister(metricEniAvailable)

	metricEniNodesAtCapacity = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: eniSubsystem,
		Name:      "nodes_at_capacity",
		Help:      "Number of nodes unable to allocate more addresses",
	})
	mustRegister(metricEniNodesAtCapacity)

	metricEniAwsApiDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Subsystem: eniSubsystem,
		Name:      "aws_api_duration_seconds",
		Help:      "Duration of interactions with AWS API",
	}, []string{"operation", "responseCode"})
	mustRegister(metricEniAwsApiDuration)

	metricEniResync = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: eniSubsystem,
		Name:      "resync_total",
		Help:      "Number of resync operations to synchronize AWS EC2 metadata",
	})
	mustRegister(metricEniResync)

	go func() {
		// The Handler function provides a default handler to expose metrics
		// via an HTTP server. "/metrics" is the usual endpoint for that.
		http.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
		log.Fatal(http.ListenAndServe(metricsAddress, nil))
	}()
}

func mustRegister(c ...prometheus.Collector) {
	registry.MustRegister(c...)
}
