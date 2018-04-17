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
	"strconv"

	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/envoy/cilium"
	"github.com/cilium/cilium/pkg/envoy/envoy/api/v2/core"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

type Repository interface {
	// Takes sanitized rules
	Add(rules ...api.Rule)
	Remove(labels labels.LabelArray)
	Clear()
}

type IdentityPolicyResolver interface {
	ResolveIdentityPolicy(identity identity.NumericIdentity) IdentityPolicy
}

type IdentityCache func() identity.IdentityCache

func ResolveIdentityPolicy(rules api.Rules, identityCache identity.IdentityCache, identityToResolve identity.NumericIdentity) *cilium.NetworkPolicy {

	identityLabels, ok := identityCache[identityToResolve]
	if !ok {
		return nil
	}

	// List which tracks rules which select the identity for which policy is
	// being resolved. This is done because the rules must be passed over twice,
	// and there's no point in traversing over the same set of rules multiple
	// times if we can detect on the first pass if the rule selects the identity.
	selectingRules := api.Rules{}

	// Sets of identities which track identities that are denied upon ingress
	// and egress, and identities which are not denied (i.e., not members of the
	// sets of denied identities). The union of both sets for ingress and egress
	// should always equal the set of identities provided in the identity cache.
	notDeniedIngressIdentities := map[identity.NumericIdentity]labels.LabelArray{}
	deniedIngressIdentities := map[identity.NumericIdentity]labels.LabelArray{}
	notDeniedEgressIdentities := map[identity.NumericIdentity]labels.LabelArray{}
	deniedEgressIdentities := map[identity.NumericIdentity]labels.LabelArray{}

	identityPolicy := cilium.NetworkPolicy{
		Name:                   "",
		Policy:                 uint64(identityToResolve.Uint32()),
		IngressPerPortPolicies: make([]*cilium.PortNetworkPolicy, 0),
		EgressPerPortPolicies:  make([]*cilium.PortNetworkPolicy, 0),
	}

	// First, iterate over the rules and determine the set of identities which
	// are allowed by FromRequires and ToRequires. Update the set of denied
	// identities as well. These requirements form a conjunction across all
	// rules.
	for _, rule := range rules {
		// If rule doesn't select this identity, skip it.
		if rule.EndpointSelector.Matches(identityLabels) {

			// Track that this rule indeed selects this endpoint. When we
			// iterate over the rules again, we don't want to have to check
			// again if we already can know which rules select an endpoint.
			selectingRules = append(selectingRules, rule)

			// First, iterate over Ingress and Egress rules for 'FromRequires'
			// and 'ToRequires'. This is because these requirements apply across
			// all rules; we need to see which identities are allowed
			// by all rules. We will need to perform a second pass over the
			// rules later.
			for remoteIdentity, remoteIdentityLabels := range identityCache {
				for _, ingressRule := range rule.Ingress {
					for _, fromRequires := range ingressRule.FromRequires {
						computeAllowedAndDeniedIdentitySets(fromRequires, remoteIdentity, remoteIdentityLabels, notDeniedIngressIdentities, deniedIngressIdentities)
					}
				}
				for _, egressRule := range rule.Egress {
					for _, toRequires := range egressRule.ToRequires {
						computeAllowedAndDeniedIdentitySets(toRequires, remoteIdentity, remoteIdentityLabels, notDeniedEgressIdentities, deniedEgressIdentities)
					}
				}
			}
		}
	}

	// If we haven't denied any identities explicitly at ingress or egress,
	// set list of identities which have not been denied to all identities.
	if len(deniedIngressIdentities) == 0 {
		for k, v := range identityCache {
			notDeniedIngressIdentities[k] = v
		}
	}
	if len(deniedEgressIdentities) == 0 {
		for k, v := range identityCache {
			notDeniedEgressIdentities[k] = v
		}
	}

	// Only iterate over the list of rules which select this endpoint for
	// further policy evaluation. Given that we have the list of allowed / denied
	// identities for ingress and egress, we only have to iterate over the allowed
	// identities for creation of a NetworkPolicy object which will contain the translated,
	// but not yet optimized, policy applying to the identity for which policy
	// is being generated.
	for _, rule := range selectingRules {
		for _, ingressRule := range rule.Ingress {
			// Iterate over all identities in reference to this ingress rule,
			// and add to the translated policy accordingly.
			// TODO: only do a loop here if rule contains 'FromEndpoints'.
			for allowedIngressIdentity, lbls := range notDeniedIngressIdentities {
				// If the rule restricts at L3 (label-based), see if the rule
				// allows the current identity over which we are iterating.
				sourceEndpointSelectors := ingressRule.GetSourceEndpointSelectors()
				if len(sourceEndpointSelectors) > 0 {
					for _, sel := range sourceEndpointSelectors {
						if sel.Matches(lbls) {
							remotePolicies := computeRemotePolicies(sel, allowedIngressIdentity, deniedIngressIdentities)
							ingressPerPortPolicies := computePortNetworkPolicy(ingressRule.ToPorts, remotePolicies)
							identityPolicy.IngressPerPortPolicies = append(identityPolicy.IngressPerPortPolicies, ingressPerPortPolicies...)
						}

					}
				} else {
					// This rule is L4-only (and thus implicitly allows traffic
					// from all endpoints at L3).
					// However, if there are any identities to which traffic is
					// denied (due to restrictions in FromRequires), we cannot
					// actually say that all traffic is allowed at L3; instead,
					// we have to explicitly specify what is allowed in terms of
					// each identity.
					remotePolicies := computeRemotePolicies(api.WildcardEndpointSelector, allowedIngressIdentity, deniedIngressIdentities)
					ingressPerPortPolicies := computePortNetworkPolicy(ingressRule.ToPorts, remotePolicies)
					identityPolicy.IngressPerPortPolicies = append(identityPolicy.IngressPerPortPolicies, ingressPerPortPolicies...)
					if len(remotePolicies) == 0 {
						// If all traffic is allowed for all endpoints, no need
						// to compute for other identities for this rule.
						break
					}
				}
			}
		}

		for _, egressRule := range rule.Egress {
			// Iterate over all identities in reference to this ingress rule,
			// and add to the translated policy accordingly.
			// TODO: only do a loop here if rule contains 'FromEndpoints'.
			for allowedEgressIdentity, lbls := range notDeniedEgressIdentities {
				// If the rule restricts at L3 (label-based), see if the rule
				// allows the current identity over which we are iterating.
				destinationEndpointSelectors := egressRule.GetDestinationEndpointSelectors()
				if len(destinationEndpointSelectors) > 0 {
					for _, sel := range destinationEndpointSelectors {
						if sel.Matches(lbls) {
							remotePolicies := computeRemotePolicies(sel, allowedEgressIdentity, deniedEgressIdentities)
							egressPerPortPolicies := computePortNetworkPolicy(egressRule.ToPorts, remotePolicies)
							identityPolicy.IngressPerPortPolicies = append(identityPolicy.EgressPerPortPolicies, egressPerPortPolicies...)
						}

					}
				} else {
					// This rule is L4-only (and thus implicitly allows traffic
					// from all endpoints at L3).
					// However, if there are any identities to which traffic is
					// denied (due to restrictions in ToRequires), we cannot
					// actually say that all traffic is allowed at L3; instead,
					// we have to explicitly specify what is allowed in terms of
					// each identity.
					remotePolicies := computeRemotePolicies(api.WildcardEndpointSelector, allowedEgressIdentity, deniedEgressIdentities)
					egressPerPortPolicies := computePortNetworkPolicy(egressRule.ToPorts, remotePolicies)
					identityPolicy.EgressPerPortPolicies = append(identityPolicy.EgressPerPortPolicies, egressPerPortPolicies...)
					if len(remotePolicies) == 0 {
						// If all traffic is allowed for all endpoints, no need
						// to compute for other identities for this rule.
						break
					}
				}
			}
		}

	}
	envoy.SortPortNetworkPolicies(identityPolicy.IngressPerPortPolicies)

	return &identityPolicy
}

func computeRemotePolicies(remoteEndpointSelector api.EndpointSelector, numericIdentity identity.NumericIdentity, deniedIdentities map[identity.NumericIdentity]labels.LabelArray) []uint64 {
	var remotePolicies []uint64
	if !remoteEndpointSelector.IsWildcard() || len(deniedIdentities) > 0 {
		remotePolicies = append(remotePolicies, uint64(numericIdentity))

	}
	return remotePolicies
}

func computePortNetworkPolicy(portRules []api.PortRule, remotePolicies []uint64) []*cilium.PortNetworkPolicy {
	portNetworkPolicies := make([]*cilium.PortNetworkPolicy, 0)
	// Rule applies at L4.
	if len(portRules) > 0 {
		for _, portRule := range portRules {
			computedPortNetworkPolicies := portRuleToPortNetworkPolicyRule(portRule, remotePolicies)
			portNetworkPolicies = append(portNetworkPolicies, computedPortNetworkPolicies...)
		}
	} else {
		// Rule applies only L3.
		portNetworkPolicy := cilium.PortNetworkPolicy{
			Rules: []*cilium.PortNetworkPolicyRule{
				{
					RemotePolicies: remotePolicies,
				},
			},
		}
		portNetworkPolicies = append(portNetworkPolicies, &portNetworkPolicy)
	}

	return portNetworkPolicies
}

func portRuleToPortNetworkPolicyRule(portRule api.PortRule, remotePolicies []uint64) []*cilium.PortNetworkPolicy {
	portNetworkPolicies := make([]*cilium.PortNetworkPolicy, 0, len(portRule.Ports))
	for _, portProtocol := range portRule.Ports {
		convertedPort, _ := strconv.Atoi(portProtocol.Port)
		convertedPortUint32 := uint32(convertedPort)

		// There can be at most two protocols (TCP, UDP).
		protocols := make([]core.SocketAddress_Protocol, 0, 2)
		switch portProtocol.Protocol {
		case api.ProtoTCP:
			protocols = append(protocols, core.SocketAddress_TCP)
		case api.ProtoUDP:
			protocols = append(protocols, core.SocketAddress_UDP)
		case api.ProtoAny:
			protocols = append(protocols, core.SocketAddress_TCP)
			protocols = append(protocols, core.SocketAddress_UDP)
		}
		for _, convertedProto := range protocols {
			portNetworkPolicy := cilium.PortNetworkPolicy{
				Port:     convertedPortUint32,
				Protocol: convertedProto,
			}

			portNetworkPolicyRule := cilium.PortNetworkPolicyRule{
				RemotePolicies: remotePolicies,
			}
			if portRule.Rules != nil {
				if len(portRule.Rules.HTTP) > 0 {
					httpRules := make([]*cilium.HttpNetworkPolicyRule, 0, len(portRule.Rules.HTTP))
					for _, httpRule := range portRule.Rules.HTTP {
						headers, _ := envoy.GetHTTPRule(&httpRule)
						httpRules = append(httpRules, &cilium.HttpNetworkPolicyRule{Headers: headers})
					}
					envoy.SortHTTPNetworkPolicyRules(httpRules)
					portNetworkPolicyRule.L7Rules = &cilium.PortNetworkPolicyRule_HttpRules{
						HttpRules: &cilium.HttpNetworkPolicyRules{
							HttpRules: httpRules,
						},
					}
				}
				// TODO Kafka
			}

			if len(remotePolicies) != 0 || portNetworkPolicyRule.L7Rules != nil {
				portNetworkPolicy.Rules = append(portNetworkPolicy.Rules, &portNetworkPolicyRule)
			}
			portNetworkPolicies = append(portNetworkPolicies, &portNetworkPolicy)
		}
	}
	return portNetworkPolicies

}

func computeAllowedAndDeniedIdentitySets(requiredLabels api.EndpointSelector, numericIdentity identity.NumericIdentity, identityLabels labels.LabelArray, allowedIdentities, deniedIdentities map[identity.NumericIdentity]labels.LabelArray) {
	if requiredLabels.Matches(identityLabels) {
		if _, ok := deniedIdentities[numericIdentity]; !ok {
			allowedIdentities[numericIdentity] = identityLabels
		}
		// Now that we have a new requirement based off of the required labels,
		// we have to iterate over the set of identities which previously were
		// not denied, and remove if they do not match the current requirement
		// as well.
		for allowedIdentity, allowedIdentityLabels := range allowedIdentities {
			if !requiredLabels.Matches(allowedIdentityLabels) {
				delete(allowedIdentities, allowedIdentity)
				deniedIdentities[allowedIdentity] = allowedIdentityLabels
			}
		}
	} else {
		delete(allowedIdentities, numericIdentity)
		deniedIdentities[numericIdentity] = identityLabels
	}
}

// Yum, consumers.
type IdentityPolicyConsumer interface {
	UpdateIdentityPolicies(identityPolicies map[identity.NumericIdentity]IdentityPolicy)
}

type IdentityPolicy interface {
	NetworkPolicy() *cilium.NetworkPolicy
}
