// Copyright 2018 Authors of Cilium
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

package resolver

import (
	"fmt"

	"github.com/cilium/cilium/pkg/envoy/cilium"
	"github.com/cilium/cilium/pkg/envoy/envoy/api/v2/core"
	"github.com/cilium/cilium/pkg/resolver/sort"
	"github.com/gogo/protobuf/sortkeys"
)

// OptimizeNetworkPolicy creates the most minimally-expressive form of policyToOptimize.
// TODO ensure ordering is guaranteed?
func OptimizeNetworkPolicy(policyToOptimize *cilium.NetworkPolicy) error {
	var err error
	policyToOptimize.IngressPerPortPolicies, err = optimizePortNetworkPolicies(policyToOptimize.IngressPerPortPolicies)
	if err != nil {
		return err
	}
	sort.SortPortNetworkPolicies(policyToOptimize.IngressPerPortPolicies)
	policyToOptimize.EgressPerPortPolicies, err = optimizePortNetworkPolicies(policyToOptimize.EgressPerPortPolicies)

	return err
}

type portProtocolTuple struct {
	port     uint32
	protocol core.SocketAddress_Protocol
}

func optimizePortNetworkPolicies(portNetworkPolicy []*cilium.PortNetworkPolicy) ([]*cilium.PortNetworkPolicy, error) {
	// Create map of port and protocol to []*cilium.PortNetworkPolicy
	portProtoPortNetworkPolicyMap := map[portProtocolTuple][]*cilium.PortNetworkPolicy{}
	for _, rule := range portNetworkPolicy {
		ruleToAdd := rule
		tuple := portProtocolTuple{port: rule.Port, protocol: rule.Protocol}
		if _, ok := portProtoPortNetworkPolicyMap[tuple]; !ok {
			// Why does creating this with length > 0 append a nil value to the start of the slice? :/
			portProtoPortNetworkPolicyMap[tuple] = make([]*cilium.PortNetworkPolicy, 0)
		}
		portProtoPortNetworkPolicyMap[tuple] = append(portProtoPortNetworkPolicyMap[tuple], ruleToAdd)
	}

	if len(portProtoPortNetworkPolicyMap) == 0 {
		return nil, nil
	}

	coalescedPortNetworkPolicies := make([]*cilium.PortNetworkPolicy, 0, len(portProtoPortNetworkPolicyMap))

	for _, portNetworkPolicies := range portProtoPortNetworkPolicyMap {
		ruleForPortProto, err := coalescePortNetworkPoliciesList(portNetworkPolicies)
		if err != nil {
			return nil, err
		}
		if ruleForPortProto == nil {
			// Log warning?
			continue
		}
		coalescedPortNetworkPolicies = append(coalescedPortNetworkPolicies, ruleForPortProto)
	}

	return optimizeDirectionNetworkPolicy(coalescedPortNetworkPolicies), nil
}

func coalescePortNetworkPoliciesList(listToCoalesce []*cilium.PortNetworkPolicy) (*cilium.PortNetworkPolicy, error) {
	if len(listToCoalesce) == 0 {
		return nil, nil
	}

	coalescedPortNetworkPolicy := &cilium.PortNetworkPolicy{
		Port:     listToCoalesce[0].Port,
		Protocol: listToCoalesce[0].Protocol,
	}

	var allowsAllAtL3AndL7, restrictsAtL7, hasHTTPRules, hasKafkaRules bool
	for _, portNetworkPolicy := range listToCoalesce {
		if len(portNetworkPolicy.Rules) == 0 {
			// Rule allows all at L3 and L7 for this port.
			allowsAllAtL3AndL7 = true
		}
		for _, pnpr := range portNetworkPolicy.Rules {
			if pnpr.L7Rules != nil {
				switch x := pnpr.L7Rules.(type) {
				case *cilium.PortNetworkPolicyRule_HttpRules:
					if hasKafkaRules {
						return nil, fmt.Errorf("multiple L7 protocols cannot apply to the same L4 port and protocol")
					}
					hasHTTPRules = true
				case *cilium.PortNetworkPolicyRule_KafkaRules:
					if hasHTTPRules {
						return nil, fmt.Errorf("multiple L7 protocols cannot apply to the same L4 port and protocol")
					}
					hasKafkaRules = true
				default:
					// Should never happen.
					return nil, fmt.Errorf("unsupported protocol %v", x)
				}
				// Rule specifies some type of policy at L7.
				restrictsAtL7 = true
			}
		}
	}

	if allowsAllAtL3AndL7 && restrictsAtL7 {
		// We can simply synthesize a rule that allows all L3 at the L7 protocol
		// for the specified port.
		if hasHTTPRules {
			coalescedPortNetworkPolicy.Rules = []*cilium.PortNetworkPolicyRule{
				{
					L7Rules: &cilium.PortNetworkPolicyRule_HttpRules{
						HttpRules: &cilium.HttpNetworkPolicyRules{
							HttpRules: []*cilium.HttpNetworkPolicyRule{
								{},
							},
						},
					},
				},
			}
		} else if hasKafkaRules {
			coalescedPortNetworkPolicy.Rules = []*cilium.PortNetworkPolicyRule{
				{
					L7Rules: &cilium.PortNetworkPolicyRule_KafkaRules{
						KafkaRules: &cilium.KafkaNetworkPolicyRules{
							KafkaRules: []*cilium.KafkaNetworkPolicyRule{
								{},
							},
						},
					},
				},
			}
		}
		return coalescedPortNetworkPolicy, nil
	} else if allowsAllAtL3AndL7 {
		coalescedPortNetworkPolicy.Rules = []*cilium.PortNetworkPolicyRule{}
		return coalescedPortNetworkPolicy, nil
	}

	for _, portNetworkPolicy := range listToCoalesce {
		if coalescedPortNetworkPolicy.Rules == nil && len(portNetworkPolicy.Rules) > 0 {
			coalescedPortNetworkPolicy.Rules = make([]*cilium.PortNetworkPolicyRule, 0, len(portNetworkPolicy.Rules))
		}
		if coalescedPortNetworkPolicy.Rules != nil {
			coalescedPortNetworkPolicy.Rules = append(coalescedPortNetworkPolicy.Rules, portNetworkPolicy.Rules...)
		}
	}
	return coalescedPortNetworkPolicy, nil
}

// portNetworkPolicyIsL3Only returns whether a PortNetworkPolicy is L3-only,
// i.e. if it has port 0. As a sanity check, this method panics if the rule has
// both port 0 and any L7 rules, which must never happen.
func portNetworkPolicyIsL3Only(pnp *cilium.PortNetworkPolicy) bool {
	if pnp.Port != 0 {
		return false
	}
	for _, rule := range pnp.Rules {
		if rule.L7Rules != nil {
			log.Fatalf("PortNetworkPolicy has both port 0 and L7 rules: %v", pnp)
		}
	}
	return true
}

// optimizePortNetworkPolicyRuleRemotePolicies removes from the given rule the
// remote policies that are already allowed, as listed in the given
// allowedRemotePolicies set.
// Returns true if the rule is to be kept after optimization, or false if the
// rule doesn't match any remote policies and is to be discarded.
func optimizePortNetworkPolicyRuleRemotePolicies(allowedRemotePolicies map[uint64]bool,
	rule *cilium.PortNetworkPolicyRule) bool {

	// The rule allows all remote policies. Nothing to optimize. Keep the
	// rule as-is.
	if len(rule.RemotePolicies) == 0 {
		return true
	}

	// Remove from the rule all the remote policies that are already allowed.
	// Preserve the order.
	newRemotePolicies := make([]uint64, 0, len(rule.RemotePolicies))
	for _, remotePolicy := range rule.RemotePolicies {
		// The remote policy is not already allowed. Keep it.
		if !allowedRemotePolicies[remotePolicy] {
			newRemotePolicies = append(newRemotePolicies, remotePolicy)
		}
	}

	// All of the rule's remote policies are already allowed.
	if len(newRemotePolicies) == 0 {
		// Don't mark rule as redundant if there are no new remote policies to
		// which this rule applies; practically, this means that all traffic
		// is already allowed at L3 for the remote policies in this rule.
		// Instead, have rule for that port which  allows all at L7 for the
		// specified protocol in the rule. This allows traffic to be forwarded
		// to the proxy for that port.
		switch rule.L7Rules.(type) {
		case *cilium.PortNetworkPolicyRule_HttpRules:
			rule.L7Rules = &cilium.PortNetworkPolicyRule_HttpRules{
				HttpRules: &cilium.HttpNetworkPolicyRules{
					HttpRules: []*cilium.HttpNetworkPolicyRule{
						{},
					},
				},
			}
		}
		return true
	}

	rule.RemotePolicies = newRemotePolicies
	return true
}

func optimizeDirectionNetworkPolicy(perPortPolicies []*cilium.PortNetworkPolicy) []*cilium.PortNetworkPolicy {
	if len(perPortPolicies) == 0 {
		return perPortPolicies
	}

	// List remote policies allowed by L3-only policies (each L3-only policy
	// both wildcards the L4 port (its port is 0) and has no L7 rules).
	// There can be at most two L3-only policies: one for TCP, and one for
	// UDP. We only keep a map of allowed remote policies for each L3-only
	// policy, since this is its only useful information.
	allowedRemotePolicies := make(map[uint64]bool)
	for _, pnp := range perPortPolicies {
		if portNetworkPolicyIsL3Only(pnp) {
			for _, rule := range pnp.Rules {
				for _, remotePolicy := range rule.RemotePolicies {
					allowedRemotePolicies[remotePolicy] = true
				}
			}
		}
	}

	// If there are no L3-only rules, there is nothing to optimize.
	if len(allowedRemotePolicies) == 0 {
		return perPortPolicies
	}

	// Remove remote policies from L4/L7 rules when they are already covered by
	// L3-only rules.

	var newPerPortPolicies []*cilium.PortNetworkPolicy
	for _, pnp := range perPortPolicies {
		if newPerPortPolicies == nil {
			newPerPortPolicies = make([]*cilium.PortNetworkPolicy, 0, len(perPortPolicies))
		}
		// L3-only rule. Keep it.
		if portNetworkPolicyIsL3Only(pnp) {
			// TODO put into separate function (coalesce L3 rule)
			remotePoliciesToAdd := make([]uint64, 0, len(allowedRemotePolicies))
			for remotePolicy := range allowedRemotePolicies {
				remotePoliciesToAdd = append(remotePoliciesToAdd, remotePolicy)
			}
			sortkeys.Uint64s(remotePoliciesToAdd)
			l3OnlyPNP := &cilium.PortNetworkPolicy{
				Protocol: pnp.Protocol,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: remotePoliciesToAdd,
					},
				},
				ProtocolWildcard: true,
			}
			newPerPortPolicies = append(newPerPortPolicies, l3OnlyPNP)
			continue
		}

		// TODO - coalesce PortNetworkPolicyRules for the same port/proto
		// which allow only at L3.

		// No L3-only rule found for this L4 protocol. Keep all the rules
		// for this L4 protocol as-is.
		if len(allowedRemotePolicies) == 0 {
			newPerPortPolicies = append(newPerPortPolicies, pnp)
			continue
		}

		// Keep L4 rules that allow all remote policies for an L4 port.
		if len(pnp.Rules) == 0 {
			newPerPortPolicies = append(newPerPortPolicies, pnp)
			continue
		}

		// Optimize the rules for the port network policy.
		newRules := make([]*cilium.PortNetworkPolicyRule, 0, len(pnp.Rules))
		for _, rule := range pnp.Rules {
			if optimizePortNetworkPolicyRuleRemotePolicies(allowedRemotePolicies, rule) {
				newRules = append(newRules, rule)
			}
		}

		// Only keep the port network policy if it still has rules matching any
		// remote policies.
		if len(newRules) > 0 {
			pnp.Rules = newRules
			newPerPortPolicies = append(newPerPortPolicies, pnp)
		}
	}

	return newPerPortPolicies
}
