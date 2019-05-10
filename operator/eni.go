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
	"context"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/spanstat"
	"github.com/cilium/cilium/pkg/trigger"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ec2metadata"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/sirupsen/logrus"
)

const (
	// defaultPreAllocation is the default value for
	// CiliumNode.Spec.ENI.PreAllocate if no value is set
	defaultPreAllocation = 8

	// warningInterval is the interval for warnings which should be done
	// once and then repeated if the warning persists.
	warningInterval = time.Hour
)

var (
	ec2Client         *ec2.EC2
	metadataClient    *ec2metadata.EC2Metadata
	identityDocument  *ec2metadata.EC2InstanceIdentityDocument
	allocationTrigger *trigger.Trigger
	resyncTrigger     *trigger.Trigger
)

// instance is the minimal representation of an AWS instance as needed by the
// ENI allocator
type instance struct {
	enis map[string]*v2.ENI
}

// instanceMap is the list of all instances indexed by instance ID
type instanceMap map[string]*instance

// add adds an instance definition to the instance map. instanceMap may not be
// subject to concurrent access while add() is used.
func (m instanceMap) add(instanceID string, eni *v2.ENI) {
	i, ok := m[instanceID]
	if !ok {
		i = &instance{}
		m[instanceID] = i
	}

	if i.enis == nil {
		i.enis = map[string]*v2.ENI{}
	}

	i.enis[eni.ID] = eni
}

// tags implements generic key value tags used by AWS
type tags map[string]string

// match returns true if the required tags are all found
func (t tags) match(required tags) bool {
	for k, neededvalue := range required {
		haveValue, ok := t[k]
		if !ok || (ok && neededvalue != haveValue) {
			return false
		}
	}
	return true
}

// subnet is a representation of an AWS subnet
type subnet struct {
	// ID is the subnet ID
	ID string

	// Name is the subnet name
	Name string

	// CIDR is the CIDR associated with the subnet
	CIDR string

	// AvailabilityZone is the availability zone of the subnet
	AvailabilityZone string

	// VpcID is the VPC the subnet is in
	VpcID string

	// AvailableAddresses is the number of addresses available for
	// allocation
	AvailableAddresses int

	// Tags is the tags of the subnet
	Tags tags
}

// subnetMap indexes AWS subnets by subnet ID
type subnetMap map[string]*subnet

// instancesManager maintaines the list of instances. It must be kept up to
// date by calling resync() regularly.
type instancesManager struct {
	mutex     lock.RWMutex
	instances instanceMap
	subnets   subnetMap
}

// getSubnet returns the subnet by subnet ID
func (m *instancesManager) getSubnet(subnetID string) *subnet {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return m.subnets[subnetID]
}

// findSubnetByTags returns the subnet with the most addresses matching VPC ID,
// availability zone and all required tags
func (m *instancesManager) findSubnetByTags(vpcID, availabilityZone string, required tags) (bestSubnet *subnet) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, s := range m.subnets {
		if s.VpcID == vpcID && s.AvailabilityZone == availabilityZone && s.Tags.match(required) {
			if bestSubnet == nil || bestSubnet.AvailableAddresses < s.AvailableAddresses {
				bestSubnet = s
			}
		}
	}

	return
}

// resync fetches the list of EC2 instances and subnets and updates the local
// cache in the instanceManager
func (m *instancesManager) resync() {
	metricEniResync.Inc()

	instances, vpcs, err := getInstances()
	if err != nil {
		log.WithError(err).Warning("Unable to synchronize EC2 interface list")
		return
	}

	subnets, err := getSubnets(vpcs)
	if err != nil {
		log.WithError(err).Warning("Unable to retrieve EC2 subnets list")
		return
	}

	log.Infof("Synchronized %d ENIs and %d subnets", len(instances), len(subnets))

	m.mutex.Lock()
	m.instances = instances
	m.subnets = subnets
	m.mutex.Unlock()
}

// getENIs returns the list of ENIs associated with a particular instance
func (m *instancesManager) getENIs(instanceID string) []*v2.ENI {
	enis := []*v2.ENI{}

	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if i, ok := m.instances[instanceID]; ok {
		for _, e := range i.enis {
			enis = append(enis, e.DeepCopy())
		}
	}

	return enis
}

var instances = instancesManager{instances: instanceMap{}}

// ciliumNode represents a Kubernetes node running Cilium with an associated
// CiliumNode custom resource
type ciliumNode struct {
	// name is the name of the node
	name string

	// neededAddresses is the number of addresses currently needed to reach
	// the PreAllocate watermark
	neededAddresses int

	// resource is the link to the CiliumNode custom resource
	resource *v2.CiliumNode

	// stats provides accounting for various per node statistics
	stats nodeStatistics

	// lastMaxAdapterWarning is the timestamp when the last warning was
	// printed that this node is out of adapters
	lastMaxAdapterWarning time.Time
}

type nodeStatistics struct {
	// usedIPs is the number of IPs currently in use
	usedIPs int

	// availableIPs is the number of IPs currently available for allocation
	// by the node
	availableIPs int

	// neededIPs is the number of IPs needed to reach the PreAllocate
	// watermwark
	neededIPs int

	// remainingInterfaces is the number of ENIs that can either be
	// allocated or have not yet exhausted the ENI specific quota of
	// addresses
	remainingInterfaces int
}

type ciliumNodeMap map[string]*ciliumNode

type nodeManager struct {
	mutex lock.RWMutex
	nodes ciliumNodeMap
}

type byNeededIPs []*ciliumNode

func (a byNeededIPs) Len() int           { return len(a) }
func (a byNeededIPs) Less(i, j int) bool { return a[i].neededAddresses > a[j].neededAddresses }
func (a byNeededIPs) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

var ciliumNodes = nodeManager{nodes: ciliumNodeMap{}}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func indexExists(enis []*v2.ENI, index int64) bool {
	for _, e := range enis {
		if e.Number == int(index) {
			return true
		}
	}
	return false
}

func deriveStatus(req *aws.Request, err error) string {
	if req.HTTPResponse != nil {
		return req.HTTPResponse.Status
	}

	if err != nil {
		return "Failed"
	}

	return "OK"
}
func createNetworkInterface(toAllocate int64, subnetID, desc string, groups []string) (string, error) {
	createReq := &ec2.CreateNetworkInterfaceInput{
		Description:                    &desc,
		SecondaryPrivateIpAddressCount: &toAllocate,
		SubnetId:                       &subnetID,
	}
	for _, grp := range groups {
		createReq.Groups = append(createReq.Groups, grp)
	}

	sinceStart := spanstat.Start()
	create := ec2Client.CreateNetworkInterfaceRequest(createReq)
	resp, err := create.Send()
	metricEniAwsApiDuration.WithLabelValues("CreateNetworkInterfaceRequest", deriveStatus(create.Request, err)).Observe(sinceStart.Seconds())
	if err != nil {
		return "", err
	}

	return *resp.NetworkInterface.NetworkInterfaceId, nil
}

func deleteNetworkInterface(eniID string) error {
	delReq := &ec2.DeleteNetworkInterfaceInput{}
	delReq.NetworkInterfaceId = &eniID

	sinceStart := spanstat.Start()
	req := ec2Client.DeleteNetworkInterfaceRequest(delReq)
	_, err := req.Send()
	metricEniAwsApiDuration.WithLabelValues("DeleteNetworkInterface", deriveStatus(req.Request, err)).Observe(sinceStart.Seconds())
	return err
}

func attachNetworkInterface(index int64, instanceID, eniID string) (string, error) {
	attachReq := &ec2.AttachNetworkInterfaceInput{}
	attachReq.DeviceIndex = &index
	attachReq.InstanceId = &instanceID
	attachReq.NetworkInterfaceId = &eniID

	sinceStart := spanstat.Start()
	attach := ec2Client.AttachNetworkInterfaceRequest(attachReq)
	attachResp, err := attach.Send()
	metricEniAwsApiDuration.WithLabelValues("AttachNetworkInterface", deriveStatus(attach.Request, err)).Observe(sinceStart.Seconds())
	if err != nil {
		return "", err
	}

	return *attachResp.AttachmentId, nil
}

func modifyNetworkInterface(eniID, attachmentID string, deleteOnTermination bool) error {
	changes := &ec2.NetworkInterfaceAttachmentChanges{
		AttachmentId:        &attachmentID,
		DeleteOnTermination: &deleteOnTermination,
	}

	modifyReq := &ec2.ModifyNetworkInterfaceAttributeInput{
		Attachment:         changes,
		NetworkInterfaceId: &eniID,
	}

	sinceStart := spanstat.Start()
	modify := ec2Client.ModifyNetworkInterfaceAttributeRequest(modifyReq)
	_, err := modify.Send()
	metricEniAwsApiDuration.WithLabelValues("ModifyNetworkInterface", deriveStatus(modify.Request, err)).Observe(sinceStart.Seconds())
	return err
}

func assignPrivateIpAddresses(eniID string, addresses int64) error {
	request := ec2.AssignPrivateIpAddressesInput{
		NetworkInterfaceId:             &eniID,
		SecondaryPrivateIpAddressCount: &addresses,
	}

	sinceStart := spanstat.Start()
	req := ec2Client.AssignPrivateIpAddressesRequest(&request)
	_, err := req.Send()
	metricEniAwsApiDuration.WithLabelValues("AssignPrivateIpAddresses", deriveStatus(req.Request, err)).Observe(sinceStart.Seconds())
	return err
}

func describeNetworkInterfaces() ([]ec2.NetworkInterface, error) {
	var (
		networkInterfaces []ec2.NetworkInterface
		nextToken         string
	)

	for {
		req := &ec2.DescribeNetworkInterfacesInput{}
		if nextToken != "" {
			req.NextToken = &nextToken
		}

		sinceStart := spanstat.Start()
		listReq := ec2Client.DescribeNetworkInterfacesRequest(req)
		response, err := listReq.Send()
		metricEniAwsApiDuration.WithLabelValues("DescribeNetworkInterfaces", deriveStatus(listReq.Request, err)).Observe(sinceStart.Seconds())
		if err != nil {
			return nil, err
		}

		networkInterfaces = append(networkInterfaces, response.NetworkInterfaces...)

		if response.NextToken == nil || *response.NextToken == "" {
			break
		} else {
			nextToken = *response.NextToken
		}
	}

	return networkInterfaces, nil
}

func describeSubnets() ([]ec2.Subnet, error) {
	sinceStart := spanstat.Start()
	listReq := ec2Client.DescribeSubnetsRequest(&ec2.DescribeSubnetsInput{})
	result, err := listReq.Send()
	metricEniAwsApiDuration.WithLabelValues("DescribeSubnets", deriveStatus(listReq.Request, err)).Observe(sinceStart.Seconds())
	if err != nil {
		return nil, err
	}

	return result.Subnets, nil
}

func (n *ciliumNode) allocateENI(s *subnet, enis []*v2.ENI, neededAddresses int) error {
	scopedLog := log.WithFields(logrus.Fields{
		"instanceID":     n.resource.Spec.ENI.InstanceID,
		"securityGroups": n.resource.Spec.ENI.SecurityGroups,
		"subnetID":       s.ID,
	})

	log.Infof("Allocating ENI")

	desc := "Cilium-CNI (" + n.resource.Spec.ENI.InstanceID + ")"
	toAllocate := int64(neededAddresses + n.resource.Spec.ENI.MaxAboveWatermark)
	eniID, err := createNetworkInterface(toAllocate, s.ID, desc, n.resource.Spec.ENI.SecurityGroups)
	if err != nil {
		trackEniAllocationAttempt("ENI creation failed", s.ID)
		return fmt.Errorf("unable to create ENI: %s", err)
	}

	scopedLog = scopedLog.WithField("eniID", eniID)
	scopedLog.Info("Created new ENI")

	var index int64
	for indexExists(enis, index) {
		index++
	}

	attachmentID, err := attachNetworkInterface(index, n.resource.Spec.ENI.InstanceID, eniID)
	if err != nil {
		delErr := deleteNetworkInterface(eniID)
		if delErr != nil {
			scopedLog.WithError(delErr).Warning("Unable to undo ENI creation after failure to attach")
		}

		trackEniAllocationAttempt("ENI attachment failed", s.ID)
		return fmt.Errorf("unable to attach ENI at index %d: %s", index, err)
	}

	scopedLog = scopedLog.WithFields(logrus.Fields{
		"attachmentID": attachmentID,
		"index":        index,
	})
	scopedLog.Info("Attached ENI to instance")

	if n.resource.Spec.ENI.DeleteOnTermination {
		// We have an attachment ID from the last API, which lets us mark the
		// interface as delete on termination
		err = modifyNetworkInterface(eniID, attachmentID, n.resource.Spec.ENI.DeleteOnTermination)
		if err != nil {
			delErr := deleteNetworkInterface(eniID)
			if delErr != nil {
				scopedLog.WithError(delErr).Warning("Unable to undo ENI creation after failure to attach")
			}

			trackEniAllocationAttempt("ENI modification failed", s.ID)
			return fmt.Errorf("unable to mark ENI for deletion on termination: %s", err)
		}
	}

	trackEniAllocationAttempt("success", s.ID)
	metricEniAllocateIpOps.WithLabelValues(s.ID).Add(float64(toAllocate))

	return nil
}

// limit contains limits for adapter count and addresses
//
// Stolen from github.com/lfyt/cni-ipvlan-vpc-k8s/
type limit struct {
	Adapters int
	IPv4     int
	IPv6     int
}

var eniLimits = map[string]limit{
	"c1.medium":     {2, 6, 0},
	"c1.xlarge":     {4, 15, 0},
	"c3.large":      {3, 10, 10},
	"c3.xlarge":     {4, 15, 15},
	"c3.2xlarge":    {4, 15, 15},
	"c3.4xlarge":    {8, 30, 30},
	"c3.8xlarge":    {8, 30, 30},
	"c4.large":      {3, 10, 10},
	"c4.xlarge":     {4, 15, 15},
	"c4.2xlarge":    {4, 15, 15},
	"c4.4xlarge":    {8, 30, 30},
	"c4.8xlarge":    {8, 30, 30},
	"c5.large":      {3, 10, 10},
	"c5d.large":     {3, 10, 10},
	"c5n.large":     {3, 10, 10},
	"c5.xlarge":     {4, 15, 15},
	"c5d.xlarge":    {4, 15, 15},
	"c5n.xlarge":    {4, 15, 15},
	"c5.2xlarge":    {4, 15, 15},
	"c5d.2xlarge":   {4, 15, 15},
	"c5n.2xlarge":   {4, 15, 15},
	"c5.4xlarge":    {8, 30, 30},
	"c5d.4xlarge":   {8, 30, 30},
	"c5n.4xlarge":   {8, 30, 30},
	"c5.9xlarge":    {8, 30, 30},
	"c5d.9xlarge":   {8, 30, 30},
	"c5n.9xlarge":   {8, 30, 30},
	"c5.18xlarge":   {15, 50, 50},
	"c5d.18xlarge":  {15, 50, 50},
	"c5n.18xlarge":  {15, 50, 50},
	"cc2.8xlarge":   {8, 30, 0},
	"cg1.4xlarge":   {8, 30, 0},
	"cr1.8xlarge":   {8, 30, 0},
	"d2.xlarge":     {4, 15, 15},
	"d2.2xlarge":    {4, 15, 15},
	"d2.4xlarge":    {8, 30, 30},
	"d2.8xlarge":    {8, 30, 30},
	"f1.2xlarge":    {4, 15, 15},
	"f1.16xlarge":   {8, 50, 50},
	"g2.2xlarge":    {4, 15, 0},
	"g2.8xlarge":    {8, 30, 0},
	"g3.4xlarge":    {8, 30, 30},
	"g3.8xlarge":    {8, 30, 30},
	"g3.16xlarge":   {15, 50, 50},
	"h1.2xlarge":    {4, 15, 15},
	"h1.4xlarge":    {8, 30, 30},
	"h1.8xlarge":    {8, 30, 30},
	"h1.16xlarge":   {15, 50, 50},
	"hi1.4xlarge":   {8, 30, 0},
	"hs1.8xlarge":   {8, 30, 0},
	"i2.xlarge":     {4, 15, 15},
	"i2.2xlarge":    {4, 15, 15},
	"i2.4xlarge":    {8, 30, 30},
	"i2.8xlarge":    {8, 30, 30},
	"i3.large":      {3, 10, 10},
	"i3.xlarge":     {4, 15, 15},
	"i3.2xlarge":    {4, 15, 15},
	"i3.4xlarge":    {8, 30, 30},
	"i3.8xlarge":    {8, 30, 30},
	"i3.16xlarge":   {15, 50, 50},
	"i3.metal":      {15, 50, 50},
	"m1.small":      {2, 4, 0},
	"m1.medium":     {2, 6, 0},
	"m1.large":      {3, 10, 0},
	"m1.xlarge":     {4, 15, 0},
	"m2.xlarge":     {4, 15, 0},
	"m2.2xlarge":    {4, 30, 0},
	"m2.4xlarge":    {8, 30, 0},
	"m3.medium":     {2, 6, 0},
	"m3.large":      {3, 10, 0},
	"m3.xlarge":     {4, 15, 0},
	"m3.2xlarge":    {4, 30, 0},
	"m4.large":      {2, 10, 10},
	"m4.xlarge":     {4, 15, 15},
	"m4.2xlarge":    {4, 15, 15},
	"m4.4xlarge":    {8, 30, 30},
	"m4.10xlarge":   {8, 30, 30},
	"m4.16xlarge":   {8, 30, 30},
	"m5.large":      {3, 10, 10},
	"m5a.large":     {3, 10, 10},
	"m5d.large":     {3, 10, 10},
	"m5.xlarge":     {4, 15, 15},
	"m5a.xlarge":    {4, 15, 15},
	"m5d.xlarge":    {4, 15, 15},
	"m5.2xlarge":    {4, 15, 15},
	"m5a.2xlarge":   {4, 15, 15},
	"m5d.2xlarge":   {4, 15, 15},
	"m5.4xlarge":    {8, 30, 30},
	"m5a.4xlarge":   {8, 30, 30},
	"m5d.4xlarge":   {8, 30, 30},
	"m5.12xlarge":   {8, 30, 30},
	"m5a.12xlarge":  {8, 30, 30},
	"m5d.12xlarge":  {8, 30, 30},
	"m5.24xlarge":   {15, 50, 50},
	"m5a.24xlarge":  {15, 50, 50},
	"m5d.24xlarge":  {15, 50, 50},
	"p2.xlarge":     {4, 15, 15},
	"p2.8xlarge":    {8, 30, 30},
	"p2.16xlarge":   {8, 30, 30},
	"p3.2xlarge":    {4, 15, 15},
	"p3.8xlarge":    {8, 30, 30},
	"p3.16xlarge":   {8, 30, 30},
	"p3dn.24xlarge": {15, 50, 50},
	"r3.large":      {3, 10, 10},
	"r3.xlarge":     {4, 15, 15},
	"r3.2xlarge":    {4, 15, 15},
	"r3.4xlarge":    {8, 30, 30},
	"r3.8xlarge":    {8, 30, 30},
	"r4.large":      {3, 10, 10},
	"r4.xlarge":     {4, 15, 15},
	"r4.2xlarge":    {4, 15, 15},
	"r4.4xlarge":    {8, 30, 30},
	"r4.8xlarge":    {8, 30, 30},
	"r4.16xlarge":   {15, 50, 50},
	"r5.large":      {3, 10, 10},
	"r5d.large":     {3, 10, 10},
	"r5a.large":     {3, 10, 10},
	"r5.xlarge":     {4, 15, 15},
	"r5a.xlarge":    {4, 15, 15},
	"r5d.xlarge":    {4, 15, 15},
	"r5.2xlarge":    {4, 15, 15},
	"r5a.2xlarge":   {4, 15, 15},
	"r5d.2xlarge":   {4, 15, 15},
	"r5.4xlarge":    {8, 30, 30},
	"r5a.4xlarge":   {8, 30, 30},
	"r5d.4xlarge":   {8, 30, 30},
	"r5.12xlarge":   {8, 30, 30},
	"r5a.12xlarge":  {8, 30, 30},
	"r5d.12xlarge":  {8, 30, 30},
	"r5.24xlarge":   {15, 50, 50},
	"r5a.24xlarge":  {15, 50, 50},
	"r5d.24xlarge":  {15, 50, 50},
	"t1.micro":      {2, 2, 0},
	"t2.nano":       {2, 2, 2},
	"t2.micro":      {2, 2, 2},
	"t2.small":      {2, 4, 4},
	"t2.medium":     {3, 6, 6},
	"t2.large":      {3, 12, 12},
	"t2.xlarge":     {3, 15, 15},
	"t2.2xlarge":    {3, 15, 15},
	"x1e.xlarge":    {3, 10, 10},
	"x1e.2xlarge":   {4, 15, 15},
	"x1e.4xlarge":   {4, 15, 15},
	"x1e.8xlarge":   {4, 15, 15},
	"x1.16xlarge":   {8, 30, 30},
	"x1e.16xlarge":  {8, 30, 30},
	"x1.32xlarge":   {8, 30, 30},
	"x1e.32xlarge":  {8, 30, 30},
	"z1d.large":     {3, 10, 10},
	"z1d.xlarge":    {4, 15, 15},
	"z1d.2xlarge":   {4, 15, 15},
	"z1d.3xlarge":   {8, 30, 30},
	"z1d.6xlarge":   {8, 30, 30},
	"z1d.12xlarge":  {15, 50, 50},
}

type allocatableResources struct {
	eni                 *v2.ENI
	subnet              *subnet
	availableOnSubnet   int
	remainingInterfaces int
}

func (n *ciliumNode) canAllocate(enis []*v2.ENI, limits limit, neededAddresses int) (a allocatableResources) {
	for _, e := range enis {
		if e.Number >= n.resource.Spec.ENI.FirstInterfaceIndex && len(e.Addresses) < limits.IPv4 {
			maxAllocate := neededAddresses + n.resource.Spec.ENI.MaxAboveWatermark
			availableOnENI := min(limits.IPv4-len(e.Addresses), maxAllocate)
			if available := limits.IPv4 - len(e.Addresses); available > 0 {
				a.remainingInterfaces++
			}

			if subnet := instances.getSubnet(e.Subnet.ID); subnet != nil {
				if subnet.AvailableAddresses > 0 {
					if a.eni == nil {
						a.eni = e
						a.subnet = subnet
						a.availableOnSubnet = min(subnet.AvailableAddresses, availableOnENI)
					}

				}
			}
		}
	}

	a.remainingInterfaces += limits.Adapters - len(enis)

	return
}

func trackEniAllocationAttempt(status, subnetID string) {
	metricEniAllocateEniOps.WithLabelValues(subnetID, status).Inc()
}

func (n *ciliumNode) allocate() {
	scopedLog := log.WithField("node", n.name)

	instanceType := n.resource.Spec.ENI.InstanceType
	limits, ok := eniLimits[instanceType]
	if !ok {
		trackEniAllocationAttempt("limits unavailable", "")
		scopedLog.Errorf("Unable to determine limits of instance type '%s'", instanceType)
		return
	}

	enis := instances.getENIs(n.resource.Spec.ENI.InstanceID)
	if a := n.canAllocate(enis, limits, n.neededAddresses); a.subnet != nil {
		scopedLog = scopedLog.WithFields(logrus.Fields{
			"limit":        limits.IPv4,
			"eniID":        a.eni.ID,
			"subnetID":     a.subnet.ID,
			"availableIPs": a.subnet.AvailableAddresses,
			"neededIPs":    n.neededAddresses,
		})

		scopedLog.Infof("Allocating IP on existing ENI")

		err := assignPrivateIpAddresses(a.eni.ID, int64(a.availableOnSubnet))
		if err != nil {
			trackEniAllocationAttempt("ip assignment failed", a.subnet.ID)
			scopedLog.WithError(err).Warningf("Unable to assign %d additional private IPs to ENI %s", a.availableOnSubnet, a.eni.ID)
			return
		}

		trackEniAllocationAttempt("success", a.subnet.ID)
		metricEniAllocateIpOps.WithLabelValues(a.subnet.ID).Add(float64(a.availableOnSubnet))
		resyncTrigger.TriggerWithReason("IPs allocated")
		return
	}

	scopedLog = scopedLog.WithFields(logrus.Fields{
		"vpcID":            n.resource.Spec.ENI.VpcID,
		"availabilityZone": n.resource.Spec.ENI.AvailabilityZone,
		"subnetTags":       n.resource.Spec.ENI.SubnetTags,
	})
	scopedLog.Infof("No more IPs available, creating new ENI")

	if len(enis) >= limits.Adapters {
		// This is not a failure scenario, warn once per hour but do
		// not track as ENI allocation failure. There is a separate
		// metric to track nodes running at capacity.
		if time.Since(n.lastMaxAdapterWarning) > warningInterval {
			log.Warningf("Instance %s is out of ENIs", n.resource.Spec.ENI.InstanceID)
			n.lastMaxAdapterWarning = time.Now()
		}
		return
	}

	bestSubnet := instances.findSubnetByTags(n.resource.Spec.ENI.VpcID, n.resource.Spec.ENI.AvailabilityZone, n.resource.Spec.ENI.SubnetTags)
	if bestSubnet == nil {
		trackEniAllocationAttempt("no available subnet", "")
		scopedLog.Warning("No subnets available to allocate ENI")
		return
	}

	err := n.allocateENI(bestSubnet, enis, n.neededAddresses)
	if err == nil {
		resyncTrigger.TriggerWithReason("ENI allocated")
	}
}

func (n *ciliumNode) refresh() {
	if n.neededAddresses > 0 {
		if allocationTrigger != nil {
			allocationTrigger.TriggerWithReason(n.name)
		}
	}

	node := n.resource.DeepCopy()

	if node.Spec.IPAM.Available == nil {
		node.Spec.IPAM.Available = map[string]v2.AllocationIP{}
	}

	if node.Status.IPAM.InUse == nil {
		node.Status.IPAM.InUse = map[string]v2.AllocationIP{}
	}

	relevantENIs := instances.getENIs(n.resource.Spec.ENI.InstanceID)
	node.Status.ENI.ENIs = map[string]v2.ENI{}
	node.Spec.IPAM.Available = map[string]v2.AllocationIP{}
	for _, e := range relevantENIs {
		node.Status.ENI.ENIs[e.ID] = *e

		if e.Number < node.Spec.ENI.FirstInterfaceIndex {
			continue
		}

		for _, ip := range e.Addresses {
			node.Spec.IPAM.Available[ip] = v2.AllocationIP{Resource: e.ID}
		}
	}

	var statusErr, specErr error
	var newNode *v2.CiliumNode

	// If k8s supports status as a sub-resource, then we need to update the status separately
	k8sCapabilities := k8sversion.Capabilities()
	switch {
	case k8sCapabilities.UpdateStatus:
		if !reflect.DeepEqual(n.resource.Spec, node.Spec) {
			for retry := 0; retry < 2; retry++ {
				newNode, specErr = ciliumK8sClient.CiliumV2().CiliumNodes("default").Update(node)
				if newNode != nil {
					n.resource = newNode
				}
				if specErr == nil {
					break
				}
			}
		}

		if !reflect.DeepEqual(n.resource.Status, node.Status) {
			for retry := 0; retry < 2; retry++ {
				newNode, statusErr = ciliumK8sClient.CiliumV2().CiliumNodes("default").UpdateStatus(node)
				if newNode != nil {
					n.resource = newNode
				}
				if statusErr == nil {
					break
				}
			}
		}
	default:
		if !reflect.DeepEqual(n.resource, node) {
			for retry := 0; retry < 2; retry++ {
				newNode, specErr = ciliumK8sClient.CiliumV2().CiliumNodes("default").Update(node)
				if newNode != nil {
					n.resource = newNode
				}
				if specErr == nil {
					break
				}
			}
		}
	}

	if specErr != nil {
		log.WithError(specErr).Warningf("Unable to update spec of CiliumNode %s", node.Name)
	}

	if statusErr != nil {
		log.WithError(statusErr).Warningf("Unable to update status of CiliumNode %s", node.Name)
	}

	n.stats.usedIPs = len(node.Status.IPAM.InUse)
	n.stats.availableIPs = max(len(node.Spec.IPAM.Available)-n.stats.usedIPs, 0)
	n.stats.neededIPs = n.neededAddresses

	limits, ok := eniLimits[n.resource.Spec.ENI.InstanceType]
	if ok {
		a := n.canAllocate(relevantENIs, limits, n.neededAddresses)
		n.stats.remainingInterfaces = a.remainingInterfaces
	}
}

func (n *nodeManager) Update(resource *v2.CiliumNode) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	node, ok := n.nodes[resource.Name]
	if !ok {
		node = &ciliumNode{
			name: resource.Name,
		}
		n.nodes[node.name] = node
	}
	node.resource = resource

	requiredAddresses := resource.Spec.ENI.PreAllocate
	if requiredAddresses == 0 {
		requiredAddresses = defaultPreAllocation
	}

	availableIPs := len(resource.Spec.IPAM.Available)
	usedIPs := len(resource.Status.IPAM.InUse)
	node.neededAddresses = requiredAddresses - (availableIPs - usedIPs)
	if node.neededAddresses < 0 {
		node.neededAddresses = 0
	}

	if node.neededAddresses > 0 {
		if allocationTrigger != nil {
			allocationTrigger.TriggerWithReason(node.name)
		}
	}

	log.WithFields(logrus.Fields{
		"available":       availableIPs,
		"used":            usedIPs,
		"required":        requiredAddresses,
		"instanceID":      resource.Spec.ENI.InstanceID,
		"addressesNeeded": node.neededAddresses,
	}).Infof("Updated node %s", resource.Name)
}

func (n *nodeManager) Delete(nodeName string) {
	n.mutex.Lock()
	delete(n.nodes, nodeName)
	n.mutex.Unlock()
}

func (n *nodeManager) allocateForNode(nodeName string) {
	n.mutex.RLock()
	defer n.mutex.RUnlock()
	node, ok := n.nodes[nodeName]
	if ok {
		node.allocate()
	}
}

func (n *nodeManager) refresh() {
	var totalUsed, totalAvailable, totalNeeded, remainingInterfaces, nodesAtCapacity int

	n.mutex.RLock()
	defer n.mutex.RUnlock()

	list := make(byNeededIPs, len(n.nodes))
	index := 0
	for _, node := range n.nodes {
		list[index] = node
		index++
	}

	// Sort by number of needed IPs
	sort.Sort(list)

	for _, node := range list {
		node.refresh()
		totalUsed += node.stats.usedIPs
		totalAvailable += node.stats.availableIPs
		totalNeeded += node.stats.neededIPs
		remainingInterfaces += node.stats.remainingInterfaces

		if remainingInterfaces == 0 && totalAvailable == 0 {
			nodesAtCapacity++
		}

	}

	metricEniIPsAllocated.WithLabelValues("used").Set(float64(totalUsed))
	metricEniIPsAllocated.WithLabelValues("available").Set(float64(totalAvailable))
	metricEniIPsAllocated.WithLabelValues("needed").Set(float64(totalNeeded))
	metricEniAvailable.Set(float64(remainingInterfaces))
	metricEniNodesAtCapacity.Set(float64(nodesAtCapacity))
}

func newEc2Filter(name string, values ...string) *ec2.Filter {
	filter := &ec2.Filter{
		Name: aws.String(name),
	}
	for _, value := range values {
		filter.Values = append(filter.Values, value)
	}
	return filter
}

func parseAndAddENI(iface *ec2.NetworkInterface, instances instanceMap, vpcs map[string]string) error {
	var availabilityZone, instanceID string

	if iface.PrivateIpAddress == nil {
		return fmt.Errorf("ENI has no IP address")
	}

	eni := v2.ENI{
		IP:             *iface.PrivateIpAddress,
		SecurityGroups: []string{},
		Addresses:      []string{},
	}

	if iface.AvailabilityZone != nil {
		availabilityZone = *iface.AvailabilityZone
	}

	if iface.MacAddress != nil {
		eni.MAC = *iface.MacAddress
	}

	if iface.NetworkInterfaceId != nil {
		eni.ID = *iface.NetworkInterfaceId
	}

	if iface.Description != nil {
		eni.Description = *iface.Description
	}

	if iface.Attachment != nil {
		if iface.Attachment.DeviceIndex != nil {
			eni.Number = int(*iface.Attachment.DeviceIndex)
		}

		if iface.Attachment.InstanceId != nil {
			instanceID = *iface.Attachment.InstanceId
		}
	}

	if iface.SubnetId != nil {
		eni.Subnet.ID = *iface.SubnetId
	}

	if iface.VpcId != nil {
		eni.VPC.ID = *iface.VpcId
	}

	for _, ip := range iface.PrivateIpAddresses {
		if ip.PrivateIpAddress != nil {
			eni.Addresses = append(eni.Addresses, *ip.PrivateIpAddress)
		}
	}

	for _, g := range iface.Groups {
		if g.GroupId != nil {
			eni.SecurityGroups = append(eni.SecurityGroups, *g.GroupId)
		}
	}

	instances.add(instanceID, &eni)
	vpcs[eni.VPC.ID] = availabilityZone
	return nil
}

// getInstances returns the list of all instances including their ENIs as instanceMap
func getInstances() (instanceMap, map[string]string, error) {
	instances := instanceMap{}
	vpcs := map[string]string{}

	networkInterfaces, err := describeNetworkInterfaces()
	if err != nil {
		return nil, nil, err
	}

	for _, iface := range networkInterfaces {
		err := parseAndAddENI(&iface, instances, vpcs)
		if err != nil {
			log.WithError(err).Warning("Unable to convert NetworkInterface to internal representation")
		}
	}

	return instances, vpcs, nil
}

// getSubnets returns all EC2 subnets as a subnetMap
func getSubnets(vpcs map[string]string) (subnetMap, error) {
	subnets := subnetMap{}

	subnetList, err := describeSubnets()
	if err != nil {
		return nil, err
	}

	for _, s := range subnetList {
		subnet := &subnet{
			ID:                 *s.SubnetId,
			CIDR:               *s.CidrBlock,
			AvailableAddresses: int(*s.AvailableIpAddressCount),
			Tags:               map[string]string{},
		}

		if s.AvailabilityZone != nil {
			subnet.AvailabilityZone = *s.AvailabilityZone
		}

		if s.VpcId != nil {
			subnet.VpcID = *s.VpcId
		}

		for _, tag := range s.Tags {
			if *tag.Key == "Name" {
				subnet.Name = *tag.Value
			} else {
				subnet.Tags[*tag.Key] = *tag.Value
			}
		}

		subnets[subnet.ID] = subnet
	}

	return subnets, nil
}

func startENIAllocator() error {
	log.Info("Starting ENI allocator...")

	cfg, err := external.LoadDefaultAWSConfig()
	if err != nil {
		return fmt.Errorf("unable to load AWS configuration: %s", err)
	}

	log.Infof("Retrieving own metadata from EC2 metadata server...")
	metadataClient = ec2metadata.New(cfg)
	instance, err := metadataClient.GetInstanceIdentityDocument()
	if err != nil {
		return fmt.Errorf("unable to retrieve instance identity document: %s", err)
	}

	allocationTrigger, err = trigger.NewTrigger(trigger.Parameters{
		Name:        "eni-allocation",
		MinInterval: 5 * time.Second,
		TriggerFunc: func(reasons []string) {
			for _, nodeName := range reasons {
				ciliumNodes.allocateForNode(nodeName)
			}
		},
	})
	if err != nil {
		return fmt.Errorf("unable to initialize allocation trigger: %s", err)
	}

	resyncTrigger, err = trigger.NewTrigger(trigger.Parameters{
		Name:        "aws-resync",
		MinInterval: 15 * time.Second,
		TriggerFunc: func(reasons []string) {
			instances.resync()
		},
	})
	if err != nil {
		return fmt.Errorf("unable to initialize resync trigger: %s", err)
	}

	identityDocument = &instance
	cfg.Region = instance.Region
	ec2Client = ec2.New(cfg)

	log.Infof("Connected to metadata server")

	// Initial sync is blocking, any further sync is protected by a trigger
	// to rate limit API interactions
	instances.resync()

	mngr := controller.NewManager()
	mngr.UpdateController("eni-refresh",
		controller.ControllerParams{
			RunInterval: time.Minute,
			DoFunc: func(_ context.Context) error {
				resyncTrigger.TriggerWithReason("interval based")
				ciliumNodes.refresh()
				return nil
			},
		})

	return nil
}
