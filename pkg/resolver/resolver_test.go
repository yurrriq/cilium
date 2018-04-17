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
	"testing"

	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/envoy/cilium"
	"github.com/cilium/cilium/pkg/envoy/envoy/api/v2/core"
	envoy_api_v2_route "github.com/cilium/cilium/pkg/envoy/envoy/api/v2/route"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/golang/protobuf/ptypes/wrappers"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type ResolverTestSuite struct{}

var _ = Suite(&ResolverTestSuite{})

var (
	identity11             = identity.NumericIdentity(11)
	identity30             = identity.NumericIdentity(30)
	identity35             = identity.NumericIdentity(35)
	identitySplashBrothers = identity.NumericIdentity(41)
	identityWarriors       = identity.NumericIdentity(73)

	endpointSelectorDurant     = api.NewESFromLabels(labels.ParseSelectLabel(fmt.Sprintf("%s:%s", labels.LabelSourceK8s, "durant")))
	endpointSelectorSplashBros = api.NewESFromLabels(
		labels.ParseSelectLabel(fmt.Sprintf("%s:%s", labels.LabelSourceK8s, "steph")),
		labels.ParseSelectLabel(fmt.Sprintf("%s:%s", labels.LabelSourceK8s, "klay")))

	stephLabel  = labels.NewLabel("steph", "", labels.LabelSourceK8s)
	durantLabel = labels.NewLabel("durant", "", labels.LabelSourceK8s)
	klayLabel   = labels.NewLabel("klay", "", labels.LabelSourceK8s)

	identity11Labels = labels.LabelArray{
		klayLabel,
	}

	identity30Labels = labels.LabelArray{
		stephLabel,
	}

	identity35Labels = labels.LabelArray{
		durantLabel,
	}

	identityWarriorsLabels = labels.LabelArray{
		durantLabel,
		stephLabel,
		klayLabel,
	}

	identitySplashBrothersLabels = labels.LabelArray{
		stephLabel,
		klayLabel,
	}
)

/*func (ds *ResolverTestSuite) TestResolveIdentityPolicies(c *C) {
}*/
func (ds *ResolverTestSuite) TestAllowedDeniedIdentitySets(c *C) {

	allowedIngressIdentities := identity.IdentityCache{}
	deniedIngressIdentities := identity.IdentityCache{}

	rules := api.Rules{&api.Rule{
		EndpointSelector: endpointSelectorDurant,
		Ingress: []api.IngressRule{
			{
				FromRequires: []api.EndpointSelector{
					api.NewESFromLabels(labels.ParseSelectLabel("k8s:klay")),
				},
			},
			{
				FromRequires: []api.EndpointSelector{
					api.NewESFromLabels(labels.ParseSelectLabel("k8s:steph")),
				},
			},
			{
				FromRequires: []api.EndpointSelector{
					api.NewESFromLabels(labels.ParseSelectLabel("k8s:durant")),
				},
			},
		},
	}}

	identityCache := identity.IdentityCache{}
	identityCache[identity11] = identity11Labels
	identityCache[identity30] = identity30Labels
	identityCache[identity35] = identity35Labels
	identityCache[identityWarriors] = identityWarriorsLabels

	for remoteIdentity, remoteIdentityLabels := range identityCache {
		//fmt.Printf("remoteIdentity=%d, remoteIdentityLabels=%s\n", remoteIdentity, remoteIdentityLabels)
		for _, rule := range rules {
			for _, ingressRule := range rule.Ingress {
				//fmt.Printf("\t testing rule: %v\n", ingressRule)
				for _, fromRequires := range ingressRule.FromRequires {
					computeAllowedAndDeniedIdentitySets(fromRequires, remoteIdentity, remoteIdentityLabels, allowedIngressIdentities, deniedIngressIdentities)
				}
			}
		}
	}

	expectedAllowedIngressIdentities := identity.IdentityCache{
		identityWarriors: identityWarriorsLabels,
	}

	expectedDeniedIngressIdentities := identity.IdentityCache{
		identity11: identity11Labels,
		identity30: identity30Labels,
		identity35: identity35Labels,
	}

	c.Assert(allowedIngressIdentities, comparator.DeepEquals, expectedAllowedIngressIdentities)
	c.Assert(deniedIngressIdentities, comparator.DeepEquals, expectedDeniedIngressIdentities)

}
func (ds *ResolverTestSuite) TestComputeRemotePolicies(c *C) {
	endpointSelectorDurant := api.NewESFromLabels(labels.ParseSelectLabel(fmt.Sprintf("%s:%s", labels.LabelSourceK8s, "durant")))
	uint64Identity35 := uint64(35)
	numericIdentity35 := identity.NumericIdentity(35)
	numericIdentity23 := identity.NumericIdentity(23)

	// Case 1: endpoint selector selects all at L3, and there are no denied
	// identities; can be allowed at L3. Allow-all is treated as an empty list
	// of remote policies.
	remotePolicies := computeRemotePolicies(api.WildcardEndpointSelector, numericIdentity35, identity.IdentityCache{})
	c.Assert(len(remotePolicies), Equals, 0)

	// Case 2: Despite wildcarding at L3, still need to specify identity
	// explicitly due to presence of denied identities.
	remotePolicies = computeRemotePolicies(api.WildcardEndpointSelector, numericIdentity35, identity.IdentityCache{numericIdentity23: labels.LabelArray{}})
	c.Assert(len(remotePolicies), Equals, 1)
	c.Assert(remotePolicies[0], Equals, uint64Identity35)

	// Case 3: no wildcarding at L3, and no denied identities; must specify that
	// only remote policy which is allowed is the one provided to the function.
	remotePolicies = computeRemotePolicies(endpointSelectorDurant, numericIdentity35, identity.IdentityCache{})
	c.Assert(len(remotePolicies), Equals, 1)
	c.Assert(remotePolicies[0], Equals, uint64Identity35)

	// Case 4: no wildcarding at L3, and denied identities; must specify that
	// only remote policy which is allowed is the one provided to the function.
	remotePolicies = computeRemotePolicies(endpointSelectorDurant, numericIdentity35, identity.IdentityCache{numericIdentity23: labels.LabelArray{}})
	c.Assert(len(remotePolicies), Equals, 1)
	c.Assert(remotePolicies[0], Equals, uint64Identity35)
}
func (ds *ResolverTestSuite) TestResolveIdentityPolicyL3Only(c *C) {
	identityCache := identity.IdentityCache{}
	identityCache[identity11] = identity11Labels
	identityCache[identity30] = identity30Labels
	identityCache[identity35] = identity35Labels
	identityCache[identityWarriors] = identityWarriorsLabels
	identityCache[identitySplashBrothers] = identitySplashBrothersLabels

	rules := api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							stephLabel,
							klayLabel,
						),
					},
				},
			},
		},
	}
	splashBrothersPolicy := ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy := &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
					},
				},
			},
			{
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
		},
		EgressPerPortPolicies: []*cilium.PortNetworkPolicy{},
	}
	c.Assert(expectedPolicy, comparator.DeepEquals, splashBrothersPolicy)

	rules = api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							stephLabel,
							klayLabel,
						),
					},
				},
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							durantLabel,
						),
					},
				},
			},
		},
	}
	splashBrothersPolicy = ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy = &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identity35)},
					},
				},
			},
			{
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
					},
				},
			},
			{
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
			{
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
		},
		EgressPerPortPolicies: []*cilium.PortNetworkPolicy{},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)
}
func (ds *ResolverTestSuite) TestResolveIdentityPolicyL4Only(c *C) {
	identityCache := identity.IdentityCache{}

	identityCache[identity11] = identity11Labels
	identityCache[identity30] = identity30Labels
	identityCache[identity35] = identity35Labels
	identityCache[identityWarriors] = identityWarriorsLabels
	identityCache[identitySplashBrothers] = identitySplashBrothersLabels

	rules := api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy := ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy := &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
			},
		},
		EgressPerPortPolicies: []*cilium.PortNetworkPolicy{},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

	rules = api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
							{Port: "53", Protocol: api.ProtoUDP},
							{Port: "8080", Protocol: api.ProtoAny},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy = ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy = &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
			},
			{
				Port:     8080,
				Protocol: core.SocketAddress_TCP,
			},
			{
				Port:     53,
				Protocol: core.SocketAddress_UDP,
			},
			{
				Port:     8080,
				Protocol: core.SocketAddress_UDP,
			},
		},
		EgressPerPortPolicies: []*cilium.PortNetworkPolicy{},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

}
func (ds *ResolverTestSuite) TestResolveIdentityPolicyL3L4(c *C) {
	identityCache := identity.IdentityCache{}

	identityCache[identity11] = identity11Labels
	identityCache[identity30] = identity30Labels
	identityCache[identity35] = identity35Labels
	identityCache[identityWarriors] = identityWarriorsLabels
	identityCache[identitySplashBrothers] = identitySplashBrothersLabels

	rules := api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							stephLabel,
							klayLabel,
						),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy := ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy := &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
		},
		EgressPerPortPolicies: []*cilium.PortNetworkPolicy{},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

	rules = api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							stephLabel,
							klayLabel,
						),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							durantLabel,
						),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy = ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy = &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identity35)},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
			{
				// This duplicate rule appears twice because both rules match
				// the labels for identityWarriors.
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
		},
		EgressPerPortPolicies: []*cilium.PortNetworkPolicy{},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

	rules = api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							stephLabel,
							klayLabel,
						),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							durantLabel,
						),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy = ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy = &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identity35)},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
			{
				// This duplicate rule appears twice because both rules match
				// the labels for identityWarriors.
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
		},
		EgressPerPortPolicies: []*cilium.PortNetworkPolicy{},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

	rules = api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							stephLabel,
							klayLabel,
						),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							durantLabel,
						),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "81", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy = ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy = &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
			{
				Port:     81,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identity35)},
					},
				},
			},
			{
				Port:     81,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
		},
		EgressPerPortPolicies: []*cilium.PortNetworkPolicy{},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

	rules = api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							durantLabel,
						),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "81", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy = ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy = &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
			},
			{
				Port:     81,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identity35)},
					},
				},
			},
			{
				Port:     81,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
		},
		EgressPerPortPolicies: []*cilium.PortNetworkPolicy{},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

	rules = api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							stephLabel,
							klayLabel,
						),
					},
				},
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							durantLabel,
						),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "81", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy = ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy = &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
					},
				},
			},
			{
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
			{
				Port:     81,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identity35)},
					},
				},
			},
			{
				Port:     81,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
					},
				},
			},
		},
		EgressPerPortPolicies: []*cilium.PortNetworkPolicy{},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)
}
func (ds *ResolverTestSuite) TestResolveIdentityPolicyL7(c *C) {
	identityCache := identity.IdentityCache{}

	identityCache[identity11] = identity11Labels
	identityCache[identity30] = identity30Labels
	identityCache[identity35] = identity35Labels
	identityCache[identityWarriors] = identityWarriorsLabels
	identityCache[identitySplashBrothers] = identitySplashBrothersLabels

	rules := api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							stephLabel,
							klayLabel,
						),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{
									Method:  "GET",
									Path:    "/foo",
									Host:    "foo.cilium.io",
									Headers: []string{"header2 value", "header1"},
								},
							},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy := ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy := &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
						L7Rules: &cilium.PortNetworkPolicyRule_HttpRules{
							HttpRules: &cilium.HttpNetworkPolicyRules{
								HttpRules: []*cilium.HttpNetworkPolicyRule{
									{Headers: []*envoy_api_v2_route.HeaderMatcher{
										{
											Name:  ":authority",
											Value: "foo.cilium.io",
											Regex: &wrappers.BoolValue{Value: true},
										},
										{
											Name:  ":method",
											Value: "GET",
											Regex: &wrappers.BoolValue{Value: true},
										},
										{
											Name:  ":path",
											Value: "/foo",
											Regex: &wrappers.BoolValue{Value: true},
										},
										{
											Name: "header1",
										},
										{
											Name:  "header2",
											Value: "value",
										},
									}},
								},
							},
						},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
						L7Rules: &cilium.PortNetworkPolicyRule_HttpRules{
							HttpRules: &cilium.HttpNetworkPolicyRules{
								HttpRules: []*cilium.HttpNetworkPolicyRule{
									{Headers: []*envoy_api_v2_route.HeaderMatcher{
										{
											Name:  ":authority",
											Value: "foo.cilium.io",
											Regex: &wrappers.BoolValue{Value: true},
										},
										{
											Name:  ":method",
											Value: "GET",
											Regex: &wrappers.BoolValue{Value: true},
										},
										{
											Name:  ":path",
											Value: "/foo",
											Regex: &wrappers.BoolValue{Value: true},
										},
										{
											Name: "header1",
										},
										{
											Name:  "header2",
											Value: "value",
										},
									}},
								},
							},
						},
					},
				},
			},
		},
		EgressPerPortPolicies: []*cilium.PortNetworkPolicy{},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)

	rules = api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorSplashBros,
			Ingress: []api.IngressRule{
				{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(
							stephLabel,
							klayLabel,
						),
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{
									Path:    "/foo",
									Method:  "GET",
									Host:    "foo.cilium.io",
									Headers: []string{"header2 value", "header1"},
								},
								{
									Path:   "/bar",
									Method: "PUT",
								},
							},
						},
					}},
				},
			},
		},
	}
	splashBrothersPolicy = ResolveIdentityPolicy(rules, identityCache, identitySplashBrothers)
	expectedPolicy = &cilium.NetworkPolicy{
		Policy: uint64(identitySplashBrothers),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identitySplashBrothers)},
						L7Rules: &cilium.PortNetworkPolicyRule_HttpRules{
							HttpRules: &cilium.HttpNetworkPolicyRules{
								HttpRules: []*cilium.HttpNetworkPolicyRule{
									{
										Headers: []*envoy_api_v2_route.HeaderMatcher{
											{
												Name:  ":method",
												Value: "PUT",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name:  ":path",
												Value: "/bar",
												Regex: &wrappers.BoolValue{Value: true},
											},
										},
									},
									{
										Headers: []*envoy_api_v2_route.HeaderMatcher{
											{
												Name:  ":authority",
												Value: "foo.cilium.io",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name:  ":method",
												Value: "GET",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name:  ":path",
												Value: "/foo",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name: "header1",
											},
											{
												Name:  "header2",
												Value: "value",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			{
				Port:     80,
				Protocol: core.SocketAddress_TCP,
				Rules: []*cilium.PortNetworkPolicyRule{
					{
						RemotePolicies: []uint64{uint64(identityWarriors)},
						L7Rules: &cilium.PortNetworkPolicyRule_HttpRules{
							HttpRules: &cilium.HttpNetworkPolicyRules{
								HttpRules: []*cilium.HttpNetworkPolicyRule{
									{
										Headers: []*envoy_api_v2_route.HeaderMatcher{
											{
												Name:  ":method",
												Value: "PUT",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name:  ":path",
												Value: "/bar",
												Regex: &wrappers.BoolValue{Value: true},
											},
										},
									},
									{
										Headers: []*envoy_api_v2_route.HeaderMatcher{
											{
												Name:  ":authority",
												Value: "foo.cilium.io",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name:  ":method",
												Value: "GET",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name:  ":path",
												Value: "/foo",
												Regex: &wrappers.BoolValue{Value: true},
											},
											{
												Name: "header1",
											},
											{
												Name:  "header2",
												Value: "value",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		EgressPerPortPolicies: []*cilium.PortNetworkPolicy{},
	}
	c.Assert(splashBrothersPolicy, comparator.DeepEquals, expectedPolicy)
}
