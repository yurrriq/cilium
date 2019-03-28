// Copyright 2016-2017 Authors of Cilium
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

package lbmap

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/sirupsen/logrus"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "map-lb")

	// mutex protects access to the BPF map to guarantee atomicity if a
	// transaction must be split across multiple map access operations.
	mutex lock.RWMutex
)

const (
	// Maximum number of entries in each hashtable
	MaxEntries   = 65536
	maxFrontEnds = 256
	// MaxSeq is used by daemon for generating bpf define LB_RR_MAX_SEQ.
	MaxSeq = 31
)

var (
	// cache contains *all* services of both IPv4 and IPv6 based maps
	// combined
	cache = newLBMapCache()
)

// ServiceKey is the interface describing protocol independent key for services map.
type ServiceKey interface {
	bpf.MapKey

	// Returns true if the key is of type IPv6
	IsIPv6() bool

	// Returns the BPF map matching the key type
	Map() *bpf.Map

	// Returns the BPF Weighted Round Robin map matching the key type
	RRMap() *bpf.Map

	// Returns a RevNatValue matching a ServiceKey
	RevNatValue() RevNatValue

	// Returns the port set in the key or 0
	GetPort() uint16

	// Set the backend index (master: 0, backend: nth backend)
	SetBackend(int)

	// Return backend index
	GetBackend() int

	// ToNetwork converts fields to network byte order.
	ToNetwork() ServiceKey

	// ToHost converts fields to host byte order.
	ToHost() ServiceKey
}

// ServiceValue is the interface describing protocol independent value for services map.
type ServiceValue interface {
	bpf.MapValue

	// Returns a RevNatKey matching a ServiceValue
	RevNatKey() RevNatKey

	// Set the number of backends
	SetCount(int)

	// Get the number of backends
	GetCount() int

	// Set address to map to (left blank for master)
	SetAddress(net.IP) error

	//GetAddress() net.IP

	// Set port to map to (left blank for master)
	SetPort(uint16)

	// Get the port number
	GetPort() uint16

	// Set reverse NAT identifier
	SetRevNat(int)

	// Set Weight
	SetWeight(uint16)

	// Get Weight
	GetWeight() uint16

	// ToNetwork converts fields to network byte order.
	ToNetwork() ServiceValue

	// ToHost converts fields to host byte order.
	ToHost() ServiceValue

	LegacyBackendID() LegacyBackendID

	IsIPv6() bool
}

// TODO(brb) fix it when adding IPv6 support
type BackendValue interface {
	bpf.MapValue

	ID() uint16

	// Returns true if the value is of type IPv6
	IsIPv6() bool

	// Returns the BPF map matching the key type
	Map() *bpf.Map

	// ToNetwork converts fields to network byte order.
	ToNetwork() ServiceKey

	// ToHost converts fields to host byte order.
	ToHost() ServiceKey
}

type LegacyBackendID string

type RRSeqValue struct {
	// Length of Generated sequence
	Count uint16

	// Generated Sequence
	Idx [MaxSeq]uint16
}

func (s *RRSeqValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(s) }

func (s *RRSeqValue) String() string {
	return fmt.Sprintf("count=%d idx=%v", s.Count, s.Idx)
}

func updateService(key ServiceKey, value ServiceValue) error {
	log.WithFields(logrus.Fields{
		"frontend": key,
		"backend":  value,
	}).Debug("adding frontend for backend to BPF maps")
	if key.GetBackend() != 0 && value.RevNatKey().GetKey() == 0 {
		return fmt.Errorf("invalid RevNat ID (0) in the Service Value")
	}
	if _, err := key.Map().OpenOrCreate(); err != nil {
		return err
	}

	return key.Map().Update(key.ToNetwork(), value.ToNetwork())
}

func updateBackend(backend *Backend4) error {
	// TODO(brb) update, m???
	if _, err := backend.Map().OpenOrCreate(); err != nil {
		return err
	}
	return backend.Map().Update(backend.Key, backend.Value.ToNetwork())
}

// TODO(brb) merge with v2
// DeleteService deletes a service from the lbmap. key should be the master (i.e., with backend set to zero).
func DeleteService(key ServiceKey) error {
	mutex.Lock()
	defer mutex.Unlock()

	return deleteServiceLocked(key)
}

func deleteServiceLocked(key ServiceKey) error {
	err := key.Map().Delete(key.ToNetwork())
	if err != nil {
		return err
	}
	err = lookupAndDeleteServiceWeights(key)
	if err == nil {
		cache.delete(key)
	}
	return err
}

func lookupService(key ServiceKey) (ServiceValue, error) {
	var svc ServiceValue

	val, err := key.Map().Lookup(key.ToNetwork())
	if err != nil {
		return nil, err
	}

	if key.IsIPv6() {
		svc = val.(*Service6Value)
	} else {
		svc = val.(*Service4Value)
	}

	return svc.ToNetwork(), nil
}

// updateServiceWeights updates cilium_lb6_rr_seq or cilium_lb4_rr_seq bpf maps.
func updateServiceWeights(key ServiceKey, value *RRSeqValue) error {
	if _, err := key.RRMap().OpenOrCreate(); err != nil {
		return err
	}

	return key.RRMap().Update(key.ToNetwork(), value)
}

// lookupAndDeleteServiceWeights deletes entry from cilium_lb6_rr_seq or cilium_lb4_rr_seq
func lookupAndDeleteServiceWeights(key ServiceKey) error {
	_, err := key.RRMap().Lookup(key.ToNetwork())
	if err != nil {
		// Ignore if entry is not found.
		return nil
	}

	return key.RRMap().Delete(key.ToNetwork())
}

type RevNatKey interface {
	bpf.MapKey

	// Returns true if the key is of type IPv6
	IsIPv6() bool

	// Returns the BPF map matching the key type
	Map() *bpf.Map

	// ToNetwork converts fields to network byte order.
	ToNetwork() RevNatKey

	// Returns the key value
	GetKey() uint16
}

type RevNatValue interface {
	bpf.MapValue

	// ToNetwork converts fields to network byte order.
	ToNetwork() RevNatValue
}

func updateRevNatLocked(key RevNatKey, value RevNatValue) error {
	log.WithFields(logrus.Fields{
		logfields.BPFMapKey:   key,
		logfields.BPFMapValue: value,
	}).Debug("adding revNat to lbmap")

	if key.GetKey() == 0 {
		return fmt.Errorf("invalid RevNat ID (0)")
	}
	if _, err := key.Map().OpenOrCreate(); err != nil {
		return err
	}

	return key.Map().Update(key.ToNetwork(), value.ToNetwork())
}

func UpdateRevNat(key RevNatKey, value RevNatValue) error {
	mutex.Lock()
	defer mutex.Unlock()

	return updateRevNatLocked(key, value)
}

func deleteBackend(backendID uint16) error {
	// TODO(brb) locking
	key := NewBackend4Key(backendID)

	return key.Map().Delete(key)
}

func deleteRevNatLocked(key RevNatKey) error {
	log.WithField(logfields.BPFMapKey, key).Debug("deleting RevNatKey")

	return key.Map().Delete(key.ToNetwork())
}

func DeleteRevNat(key RevNatKey) error {
	mutex.Lock()
	defer mutex.Unlock()

	return deleteRevNatLocked(key)
}

// gcd computes the gcd of two numbers.
func gcd(x, y uint16) uint16 {
	for y != 0 {
		x, y = y, x%y
	}
	return x
}

// generateWrrSeq generates a wrr sequence based on provided weights.
func generateWrrSeq(weights []uint16) (*RRSeqValue, error) {
	svcRRSeq := RRSeqValue{}

	n := len(weights)
	if n < 2 {
		return nil, fmt.Errorf("needs at least 2 weights")
	}

	g := uint16(0)
	for i := 0; i < n; i++ {
		if weights[i] != 0 {
			g = gcd(g, weights[i])
		}
	}

	// This means all the weights are 0.
	if g == 0 {
		return nil, fmt.Errorf("all specified weights are 0")
	}

	sum := uint16(0)
	for i := range weights {
		// Normalize the weights.
		weights[i] = weights[i] / g
		sum += weights[i]
	}

	// Check if Generated seq fits in our array.
	if int(sum) > len(svcRRSeq.Idx) {
		return nil, fmt.Errorf("sum of normalized weights exceeds %d", len(svcRRSeq.Idx))
	}

	// Generate the Sequence.
	i := uint16(0)
	k := uint16(0)
	for {
		j := uint16(0)
		for j < weights[k] {
			svcRRSeq.Idx[i] = k
			i++
			j++
		}
		if i >= sum {
			break
		}
		k++
	}
	svcRRSeq.Count = sum
	return &svcRRSeq, nil
}

// updateWrrSeq updates bpf map with the generated wrr sequence.
func updateWrrSeq(fe ServiceKey, weights []uint16) error {
	sum := uint16(0)
	for _, v := range weights {
		sum += v
	}
	if sum == 0 {
		return nil
	}
	svcRRSeq, err := generateWrrSeq(weights)
	if err != nil {
		return fmt.Errorf("unable to generate weighted round robin seq for %s with value %+v: %s", fe.String(), weights, err)
	}
	return updateServiceWeights(fe, svcRRSeq)
}

func updateMasterService(fe ServiceKey, nbackends int, nonZeroWeights uint16) error {
	fe.SetBackend(0)
	zeroValue := fe.NewValue().(ServiceValue)
	zeroValue.SetCount(nbackends)
	zeroValue.SetWeight(nonZeroWeights)

	return updateService(fe, zeroValue)
}

func serviceValue2L3n4Addr(svcVal ServiceValue) *loadbalancer.L3n4Addr {
	var (
		beIP   net.IP
		bePort uint16
	)
	if svcVal.IsIPv6() {
		svc6Val := svcVal.(*Service6Value)
		beIP = svc6Val.Address.IP()
		bePort = svc6Val.Port
	} else {
		svc4Val := svcVal.(*Service4Value)
		beIP = svc4Val.Address.IP()
		bePort = svc4Val.Port
	}
	return loadbalancer.NewL3n4Addr(loadbalancer.NONE, beIP, bePort)
}

// UpdateService adds or updates the given service in the bpf maps
func UpdateService(fe ServiceKey, backends []ServiceValue, addRevNAT bool, revNATID int,
	acquireBackendID func(loadbalancer.L3n4Addr) (uint16, error),
	releaseBackendID func(uint16) error) error {

	var (
		weights         []uint16
		nNonZeroWeights uint16
		existingCount   int
	)

	// Acquire missing backend IDs

	newBackendsByLegacyID := map[LegacyBackendID]ServiceValue{}
	newBackendLegacyIDs := map[LegacyBackendID]struct{}{}
	for _, b := range backends {
		legacyID := b.LegacyBackendID()
		newBackendLegacyIDs[legacyID] = struct{}{}
		newBackendsByLegacyID[legacyID] = b
	}
	newBackendLegacyIDs = cache.missingLegacyBackendIDs(newBackendLegacyIDs)
	newBackendIDs := map[LegacyBackendID]uint16{}

	for legacyID := range newBackendLegacyIDs {
		backendID, err := acquireBackendID(*serviceValue2L3n4Addr(newBackendsByLegacyID[legacyID]))
		if err != nil {
			return fmt.Errorf("Unable to acquire backend ID for %s: %s", legacyID, err)
		}
		newBackendIDs[legacyID] = backendID
	}

	cache.addBackendIDs(newBackendIDs)

	svc, addedBackends, removedBackendIDs := cache.prepareUpdate(fe, backends)
	besValues := svc.getBackends()

	log.WithFields(logrus.Fields{
		"frontend": fe,
		"backends": besValues,
	}).Debugf("Updating BPF representation of service")

	for _, be := range besValues {
		weights = append(weights, be.GetWeight())
		if be.GetWeight() != 0 {
			nNonZeroWeights++
		}
	}

	mutex.Lock()
	defer mutex.Unlock()

	// Check if the service already exists, it is not failure scenario if
	// the services doesn't exist. That's simply a new service. Even if the
	// service cannot be looked up for an existing service, it is still
	// better to proceed and update the service, at the cost of a slightly
	// less atomic update.
	svcValue, err := lookupService(fe)
	if err == nil {
		existingCount = svcValue.GetCount()
	}

	// Create new backends
	for backendID, svcVal := range addedBackends {
		if !svcVal.IsIPv6() {
			fmt.Println("### create backend", backendID, svcVal)
			svc4Val := svcVal.(*Service4Value)
			b, err := NewBackend4(backendID, svc4Val.Address.IP(), svc4Val.Port, u8proto.All)
			if err != nil {
				return err
			}
			if err := updateBackend(b); err != nil {
				return err
			}
		}
	}

	for nsvc, be := range besValues {
		fe.SetBackend(nsvc + 1) // service count starts with 1
		if err := updateService(fe, be); err != nil {
			return fmt.Errorf("unable to update service %+v with the value %+v: %s", fe, be, err)
		}
	}

	if addRevNAT {
		zeroValue := fe.NewValue().(ServiceValue)
		zeroValue.SetRevNat(revNATID)
		revNATKey := zeroValue.RevNatKey()
		revNATValue := fe.RevNatValue()

		if err := updateRevNatLocked(revNATKey, revNATValue); err != nil {
			return fmt.Errorf("unable to update reverse NAT %+v with value %+v, %s", revNATKey, revNATValue, err)
		}
		defer func() {
			if err != nil {
				deleteRevNatLocked(revNATKey)
			}
		}()
	}

	err = updateMasterService(fe, len(besValues), nNonZeroWeights)
	if err != nil {
		return fmt.Errorf("unable to update service %+v: %s", fe, err)
	}

	err = updateWrrSeq(fe, weights)
	if err != nil {
		return fmt.Errorf("unable to update service weights for %s with value %+v: %s", fe.String(), weights, err)
	}

	// Remove old backends that are no longer needed
	for i := len(besValues) + 1; i <= existingCount; i++ {
		fe.SetBackend(i)
		if err := deleteServiceLocked(fe); err != nil {
			return fmt.Errorf("unable to delete service %+v: %s", fe, err)
		}
	}

	if !fe.IsIPv6() {
		svc4Key := fe.(*Service4Key)
		svcKeyV2 := NewService4KeyV2(svc4Key.Address.IP(), svc4Key.Port, u8proto.All, 0)

		existingCount = 0
		svcValV2, err := lookupServiceV2(svcKeyV2)
		if err == nil {
			existingCount = svcValV2.GetCount()
		}

		slot := 1
		// TODO(brb) lock

		fmt.Println("### create service", svc4Key)
		for legacyID, svcVal := range svc.backendsV2 {
			svc4Val := svcVal.(*Service4Value)
			legacySlaveSlot, found := svc.getSlaveSlot(legacyID)
			if !found {
				return fmt.Errorf("Slave slot not found for backend with legacy ID %s", legacyID)
			}
			// TODO(brb) maybe remove revNATID
			backendID := cache.getBackendIDByLegacyID(legacyID) // TODO(brb) we can extract from svcVal
			svcValV2 := NewService4ValueV2(uint16(legacySlaveSlot), backendID, uint16(revNATID), svc4Val.GetWeight())
			svcValV2.SetCount(legacySlaveSlot)
			svcKeyV2.SetSlave(slot)
			slot++
			if err := updateServiceV2(svcKeyV2, svcValV2); err != nil {
				return fmt.Errorf("Unable to update service %+v with the value %+v: %s",
					svcKeyV2, svcValV2, err)
			}

		}

		err = updateMasterServiceV2(svcKeyV2, len(svc.backendsV2), nNonZeroWeights, revNATID)
		if err != nil {
			return fmt.Errorf("unable to update service %+v: %s", svcKeyV2, err)
		}

		err = updateWrrSeqV2(svcKeyV2, weights)
		if err != nil {
			return fmt.Errorf("unable to update service weights for %s with value %+v: %s", svcKeyV2.String(), weights, err)
		}
		for i := slot; i <= existingCount; i++ {
			svcKeyV2.SetSlave(i)
			if err := deleteServiceLockedV2(svcKeyV2); err != nil {
				return fmt.Errorf("unable to delete service %+v: %s", svcKeyV2, err)
			}

		}
	}

	// Delete no longer needed backends
	for _, backendID := range removedBackendIDs {
		if err := deleteBackend(backendID); err != nil {
			return fmt.Errorf("Unable to delete backend with ID %d: %s", backendID, err)
		}
		if err := releaseBackendID(backendID); err != nil {
			return fmt.Errorf("Unable to release backend ID %d: %s", backendID, err)
		}
	}

	return nil
}

// l3n4Addr2ServiceKey converts the given l3n4Addr to a ServiceKey with the slave ID
// set to 0.
func l3n4Addr2ServiceKey(l3n4Addr loadbalancer.L3n4AddrID) ServiceKey {
	log.WithField(logfields.L3n4AddrID, l3n4Addr).Debug("converting L3n4Addr to ServiceKey")
	if l3n4Addr.IsIPv6() {
		return NewService6Key(l3n4Addr.IP, l3n4Addr.Port, 0)
	}
	return NewService4Key(l3n4Addr.IP, l3n4Addr.Port, 0)
}

// LBSVC2ServiceKeynValue transforms the SVC Cilium type into a bpf SVC type.
func LBSVC2ServiceKeynValue(svc *loadbalancer.LBSVC) (ServiceKey, []ServiceValue, error) {
	log.WithFields(logrus.Fields{
		"lbFrontend": svc.FE.String(),
		"lbBackend":  svc.BES,
	}).Debug("converting Cilium load-balancer service (frontend -> backend(s)) into BPF service")
	fe := l3n4Addr2ServiceKey(svc.FE)

	// Create a list of ServiceValues so we know everything is safe to put in the lb
	// map
	besValues := []ServiceValue{}
	for _, be := range svc.BES {
		beValue := fe.NewValue().(ServiceValue)
		if err := beValue.SetAddress(be.IP); err != nil {
			return nil, nil, err
		}
		beValue.SetPort(be.Port)
		beValue.SetRevNat(int(svc.FE.ID))
		beValue.SetWeight(be.Weight)

		besValues = append(besValues, beValue)
		log.WithFields(logrus.Fields{
			"lbFrontend": fe,
			"lbBackend":  beValue,
		}).Debug("associating frontend -> backend")
	}
	log.WithFields(logrus.Fields{
		"lbFrontend":        svc.FE.String(),
		"lbBackend":         svc.BES,
		logfields.ServiceID: fe,
		logfields.Object:    logfields.Repr(besValues),
	}).Debug("converted LBSVC (frontend -> backend(s)), to Service Key and Value")
	return fe, besValues, nil
}

// L3n4Addr2RevNatKeynValue converts the given L3n4Addr to a RevNatKey and RevNatValue.
func L3n4Addr2RevNatKeynValue(svcID loadbalancer.ServiceID, feL3n4Addr loadbalancer.L3n4Addr) (RevNatKey, RevNatValue) {
	if feL3n4Addr.IsIPv6() {
		return NewRevNat6Key(uint16(svcID)), NewRevNat6Value(feL3n4Addr.IP, feL3n4Addr.Port)
	}
	return NewRevNat4Key(uint16(svcID)), NewRevNat4Value(feL3n4Addr.IP, feL3n4Addr.Port)
}

// serviceKey2L3n4Addr converts the given svcKey to a L3n4Addr.
func serviceKey2L3n4Addr(svcKey ServiceKey) *loadbalancer.L3n4Addr {
	log.WithField(logfields.ServiceID, svcKey).Debug("creating L3n4Addr for ServiceKey")
	var (
		feIP   net.IP
		fePort uint16
	)
	if svcKey.IsIPv6() {
		svc6Key := svcKey.(*Service6Key)
		feIP = svc6Key.Address.IP()
		fePort = svc6Key.Port
	} else {
		svc4Key := svcKey.(*Service4Key)
		feIP = svc4Key.Address.IP()
		fePort = svc4Key.Port
	}
	return loadbalancer.NewL3n4Addr(loadbalancer.NONE, feIP, fePort)
}

// serviceKey2L3n4Addr converts the given svcKey to a L3n4Addr.
func serviceKey2L3n4AddrV2(svcKey *Service4KeyV2) *loadbalancer.L3n4Addr {
	log.WithField(logfields.ServiceID, svcKey).Debug("creating L3n4Addr for ServiceKey")
	var (
		feIP    net.IP
		fePort  uint16
		feProto loadbalancer.L4Type
	)
	//if svcKey.IsIPv6() {
	//	svc6Key := svcKey.(*Service6Key)
	//	feIP = svc6Key.Address.IP()
	//	fePort = svc6Key.Port
	//} else {
	//svc4Key := svcKey.(*Service4Key)
	svc4Key := svcKey
	feIP = svc4Key.Address.IP()
	fePort = svc4Key.Port
	feProto = loadbalancer.NONE
	//}
	return loadbalancer.NewL3n4Addr(feProto, feIP, fePort)
}

// serviceKeynValue2FEnBE converts the given svcKey and svcValue to a frontend in the
// form of L3n4AddrID and backend in the form of L3n4Addr.
func serviceKeynValue2FEnBE(svcKey ServiceKey, svcValue ServiceValue) (*loadbalancer.L3n4AddrID, *loadbalancer.LBBackEnd) {
	var (
		beIP     net.IP
		svcID    loadbalancer.ServiceID
		bePort   uint16
		beWeight uint16
		beID     uint16
	)

	log.WithFields(logrus.Fields{
		logfields.ServiceID: svcKey,
		logfields.Object:    logfields.Repr(svcValue),
	}).Debug("converting ServiceKey and ServiceValue to frontend and backend")

	if svcKey.IsIPv6() {
		svc6Val := svcValue.(*Service6Value)
		svcID = loadbalancer.ServiceID(svc6Val.RevNat)
		beIP = svc6Val.Address.IP()
		bePort = svc6Val.Port
		beWeight = svc6Val.Weight
		beID = svc6Val.Count
	} else {
		svc4Val := svcValue.(*Service4Value)
		svcID = loadbalancer.ServiceID(svc4Val.RevNat)
		beIP = svc4Val.Address.IP()
		bePort = svc4Val.Port
		beWeight = svc4Val.Weight
		beID = svc4Val.Count
	}

	feL3n4Addr := serviceKey2L3n4Addr(svcKey)
	beLBBackEnd := loadbalancer.NewLBBackEnd(beID, loadbalancer.NONE, beIP, bePort, beWeight)

	feL3n4AddrID := &loadbalancer.L3n4AddrID{
		L3n4Addr: *feL3n4Addr,
		ID:       svcID,
	}

	return feL3n4AddrID, beLBBackEnd
}

func serviceKeynValuenBackendValue2FEnBE(svcKey *Service4KeyV2, svcValue *Service4ValueV2, backendID uint16, backendValue *Backend4Value) (*loadbalancer.L3n4AddrID, *loadbalancer.LBBackEnd) {
	var (
		beIP     net.IP
		svcID    loadbalancer.ServiceID
		bePort   uint16
		beWeight uint16
		beProto  loadbalancer.L4Type
	)

	log.WithFields(logrus.Fields{
		logfields.ServiceID: svcKey,
		logfields.Object:    logfields.Repr(svcValue),
	}).Debug("converting ServiceKey and ServiceValue to frontend and backend")

	//if svcKey.IsIPv6() {
	//	svc6Val := svcValue.(*Service6Value)
	//	svcID = loadbalancer.ServiceID(svc6Val.RevNat)
	//	beIP = svc6Val.Address.IP()
	//	bePort = svc6Val.Port
	//	beWeight = svc6Val.Weight
	//} else {
	//svc4Val := svcValue.(*Service4Value)
	svcID = loadbalancer.ServiceID(svcValue.RevNat)
	beIP = backendValue.Address.IP()
	bePort = backendValue.Port
	beWeight = svcValue.Weight
	beProto = loadbalancer.NONE
	//}

	feL3n4Addr := serviceKey2L3n4AddrV2(svcKey)
	beLBBackEnd := loadbalancer.NewLBBackEnd(backendID, beProto, beIP, bePort, beWeight)

	feL3n4AddrID := &loadbalancer.L3n4AddrID{
		L3n4Addr: *feL3n4Addr,
		ID:       svcID,
	}

	return feL3n4AddrID, beLBBackEnd
}

// RevNat6Value2L3n4Addr converts the given RevNat6Value to a L3n4Addr.
func revNat6Value2L3n4Addr(revNATV *RevNat6Value) *loadbalancer.L3n4Addr {
	return loadbalancer.NewL3n4Addr(loadbalancer.NONE, revNATV.Address.IP(), revNATV.Port)
}

// revNat4Value2L3n4Addr converts the given RevNat4Value to a L3n4Addr.
func revNat4Value2L3n4Addr(revNATV *RevNat4Value) *loadbalancer.L3n4Addr {
	return loadbalancer.NewL3n4Addr(loadbalancer.NONE, revNATV.Address.IP(), revNATV.Port)
}

// revNatValue2L3n4AddrID converts the given RevNatKey and RevNatValue to a L3n4AddrID.
func revNatValue2L3n4AddrID(revNATKey RevNatKey, revNATValue RevNatValue) *loadbalancer.L3n4AddrID {
	var (
		svcID loadbalancer.ServiceID
		be    *loadbalancer.L3n4Addr
	)
	if revNATKey.IsIPv6() {
		revNat6Key := revNATKey.(*RevNat6Key)
		svcID = loadbalancer.ServiceID(revNat6Key.Key)

		revNat6Value := revNATValue.(*RevNat6Value)
		be = revNat6Value2L3n4Addr(revNat6Value)
	} else {
		revNat4Key := revNATKey.(*RevNat4Key)
		svcID = loadbalancer.ServiceID(revNat4Key.Key)

		revNat4Value := revNATValue.(*RevNat4Value)
		be = revNat4Value2L3n4Addr(revNat4Value)
	}

	return &loadbalancer.L3n4AddrID{L3n4Addr: *be, ID: svcID}
}

// DeleteRevNATBPF deletes the revNAT entry from its corresponding BPF map
// (IPv4 or IPv6) with ID id. Returns an error if the deletion operation failed.
func DeleteRevNATBPF(id loadbalancer.ServiceID, isIPv6 bool) error {
	var revNATK RevNatKey
	if isIPv6 {
		revNATK = NewRevNat6Key(uint16(id))
	} else {
		revNATK = NewRevNat4Key(uint16(id))
	}
	err := DeleteRevNat(revNATK)
	return err
}

// DumpServiceMapsToUserspace dumps the contents of both the IPv6 and IPv4
// service / loadbalancer BPF maps, and converts them to a SVCMap and slice of
// LBSVC. IPv4 maps may not be dumped depending on if skipIPv4 is enabled. If
// includeMasterBackend is true, the returned values will also include services
// which correspond to "master" backend values in the BPF maps. Returns the
// errors that occurred while dumping the maps.
func DumpServiceMapsToUserspace() (loadbalancer.SVCMap, []*loadbalancer.LBSVC, []error) {
	newSVCMap := loadbalancer.SVCMap{}
	newSVCList := []*loadbalancer.LBSVC{}
	errors := []error{}
	idCache := map[string]loadbalancer.ServiceID{}

	parseSVCEntries := func(key bpf.MapKey, value bpf.MapValue) {
		svcKey := key.(ServiceKey)
		svcValue := value.(ServiceValue)

		scopedLog := log.WithFields(logrus.Fields{
			logfields.BPFMapKey:   svcKey,
			logfields.BPFMapValue: svcValue,
		})

		scopedLog.Debug("parsing service mapping")
		fe, be := serviceKeynValue2FEnBE(svcKey, svcValue)

		// Build a cache to map frontend IP to service ID. The master
		// service key does not have the service ID set so the cache
		// needs to be built based on backend key entries.
		if k := svcValue.RevNatKey().GetKey(); k != uint16(0) {
			idCache[fe.String()] = loadbalancer.ServiceID(k)
		}

		// Do not include master services
		if svcKey.GetBackend() != 0 {
			svc := newSVCMap.AddFEnBE(fe, be, svcKey.GetBackend())
			newSVCList = append(newSVCList, svc)
		}
	}

	mutex.RLock()
	defer mutex.RUnlock()

	if option.Config.EnableIPv4 {
		err := Service4Map.DumpWithCallback(parseSVCEntries)
		if err != nil {
			errors = append(errors, err)
		}
	}

	// TODO(brb)
	//if option.Config.EnableIPv6 {
	//	err := Service6Map.DumpWithCallback(parseSVCEntries)
	//	if err != nil {
	//		errors = append(errors, err)
	//	}
	//}

	// serviceKeynValue2FEnBE() cannot fill in the service ID reliably as
	// not all BPF map entries contain the service ID. Do a pass over all
	// parsed entries and fill in the service ID
	for i := range newSVCList {
		newSVCList[i].FE.ID = idCache[newSVCList[i].FE.String()]
	}

	// Do the same for the svcMap
	for key, svc := range newSVCMap {
		svc.FE.ID = idCache[svc.FE.String()]
		newSVCMap[key] = svc
	}

	return newSVCMap, newSVCList, errors
}

// DumpRevNATMapsToUserspace dumps the contents of both the IPv6 and IPv4
// revNAT BPF maps, and stores the contents of said dumps in a RevNATMap.
// Returns the errors that occurred while dumping the maps.
func DumpRevNATMapsToUserspace() (loadbalancer.RevNATMap, []error) {

	newRevNATMap := loadbalancer.RevNATMap{}
	errors := []error{}

	parseRevNATEntries := func(key bpf.MapKey, value bpf.MapValue) {
		revNatK := key.(RevNatKey)
		revNatV := value.(RevNatValue)
		scopedLog := log.WithFields(logrus.Fields{
			logfields.BPFMapKey:   revNatK,
			logfields.BPFMapValue: revNatV,
		})

		scopedLog.Debug("parsing BPF revNAT mapping")
		fe := revNatValue2L3n4AddrID(revNatK, revNatV)
		newRevNATMap[fe.ID] = fe.L3n4Addr
	}

	mutex.RLock()
	defer mutex.RUnlock()

	if option.Config.EnableIPv4 {
		if err := RevNat4Map.DumpWithCallback(parseRevNATEntries); err != nil {
			err = fmt.Errorf("error dumping RevNat4Map: %s", err)
			errors = append(errors, err)
		}
	}

	if option.Config.EnableIPv6 {
		if err := RevNat6Map.DumpWithCallback(parseRevNATEntries); err != nil {
			err = fmt.Errorf("error dumping RevNat6Map: %s", err)
			errors = append(errors, err)
		}
	}

	return newRevNATMap, errors

}

// RestoreService restores a single service in the cache. This is required to
// guarantee consistent backend ordering
func RestoreService(svc loadbalancer.LBSVC, v2Exists bool) error {
	return cache.restoreService(svc, v2Exists)
}

func DeleteServiceV2(svc loadbalancer.L3n4AddrID,
	releaseBackendID func(uint16) error) error {

	svcKey := NewService4KeyV2(svc.IP, svc.Port, u8proto.All, 0)
	backendsToRemove, backendsCount, err := cache.removeServiceV2(svcKey)
	if err != nil {
		return err
	}

	for slot := 0; slot <= backendsCount; slot++ {
		svcKey.SetSlave(slot)
		if err := svcKey.MapDelete(); err != nil {
			return err
		}
	}

	for _, id := range backendsToRemove {
		if err := deleteBackend(id); err != nil {
			return fmt.Errorf("Unable to delete backend with ID %d: %s", id, err)
		}
		if err := releaseBackendID(id); err != nil {
			return fmt.Errorf("Unable to release backend ID %d: %s", id, err)
		}
	}

	return nil
}

// LBSVC2ServiceKeynValuenBackendValueV2 transforms the SVC Cilium type into a bpf SVC v2 type.
func LBSVC2ServiceKeynValuenBackendV2(svc *loadbalancer.LBSVC) (*Service4KeyV2, []*Service4ValueV2, []*Backend4, error) {
	log.WithFields(logrus.Fields{
		"lbFrontend": svc.FE.String(),
		"lbBackend":  svc.BES,
	}).Debug("converting Cilium load-balancer service (frontend -> backend(s)) into BPF service")
	svcKey, err := l3n4Addr2ServiceKeyV2(svc.FE)
	if err != nil {
		return nil, nil, nil, err
	}

	backends := []*Backend4{}
	svcValues := []*Service4ValueV2{}
	for _, be := range svc.BES {
		//svcValue := svcKey.NewValue().(ServiceValue)
		svcValue := svcKey.NewValue().(*Service4ValueV2)
		backend, err := lbBackEnd2Backend(be)
		if err != nil {
			return nil, nil, nil, err
		}

		svcValue.SetRevNat(int(svc.FE.ID))
		svcValue.SetWeight(be.Weight)
		svcValue.SetBackendID(uint16(be.ID))

		backends = append(backends, backend)
		svcValues = append(svcValues, svcValue)
		log.WithFields(logrus.Fields{
			"lbFrontend": svcKey,
			"lbBackend":  svcValue,
		}).Debug("associating frontend -> backend")
	}
	log.WithFields(logrus.Fields{
		"lbFrontend":        svc.FE.String(),
		"lbBackend":         svc.BES,
		logfields.ServiceID: svcKey,
		logfields.Object:    logfields.Repr(svcValues),
	}).Debug("converted LBSVC (frontend -> backend(s)), to Service Key and Value")
	return svcKey, svcValues, backends, nil
}

// l3n4Addr2ServiceKeyV2 converts the given l3n4Addr to a ServiceKey (v2) with the slave ID
// set to 0.
func l3n4Addr2ServiceKeyV2(l3n4Addr loadbalancer.L3n4AddrID) (*Service4KeyV2, error) {
	log.WithField(logfields.L3n4AddrID, l3n4Addr).Debug("converting L3n4Addr to ServiceKey")
	//if l3n4Addr.IsIPv6() {
	//	return NewService6Key(l3n4Addr.IP, l3n4Addr.Port, 0)
	//}

	return NewService4KeyV2(l3n4Addr.IP, l3n4Addr.Port, u8proto.All, 0), nil
}

func lbBackEnd2Backend(be loadbalancer.LBBackEnd) (*Backend4, error) {
	//if be.IsIPv6() {
	//	return ...
	//}

	return NewBackend4(uint16(be.ID), be.IP, be.Port, u8proto.All)
}

func lookupServiceV2(key *Service4KeyV2) (*Service4ValueV2, error) {
	var svc *Service4ValueV2

	val, err := key.Map().Lookup(key.ToNetwork())
	if err != nil {
		return nil, err
	}

	//if key.IsIPv6() {
	//	svc = val.(*Service6Value)
	//} else {
	//	svc = val.(*Service4Value)
	//}

	svc = val.(*Service4ValueV2)

	return svc.ToNetwork(), nil
}

func updateServiceV2(key *Service4KeyV2, value *Service4ValueV2) error {
	log.WithFields(logrus.Fields{
		"frontend": key,
		"backend":  value,
	}).Debug("adding frontend for backend to BPF maps")
	if key.GetSlave() != 0 && value.RevNatKey().GetKey() == 0 {
		return fmt.Errorf("invalid RevNat ID (0) in the Service Value")
	}
	if _, err := key.Map().OpenOrCreate(); err != nil {
		return err
	}

	return key.Map().Update(key.ToNetwork(), value.ToNetwork())
}

func updateMasterServiceV2(fe *Service4KeyV2, nbackends int, nonZeroWeights uint16, revNATID int) error {
	fe.SetSlave(0)
	//zeroValue := fe.NewValue().(ServiceValue)
	zeroValue := fe.NewValue().(*Service4ValueV2)
	zeroValue.SetCount(nbackends)
	zeroValue.SetWeight(nonZeroWeights)
	zeroValue.SetRevNat(revNATID)

	return updateServiceV2(fe, zeroValue)
}

// updateWrrSeq updates bpf map with the generated wrr sequence.
func updateWrrSeqV2(fe *Service4KeyV2, weights []uint16) error {
	sum := uint16(0)
	for _, v := range weights {
		sum += v
	}
	if sum == 0 {
		return nil
	}
	svcRRSeq, err := generateWrrSeq(weights)
	if err != nil {
		return fmt.Errorf("unable to generate weighted round robin seq for %s with value %+v: %s", fe.String(), weights, err)
	}
	return updateServiceWeightsV2(fe, svcRRSeq)
}

// updateServiceWeightsV2 updates cilium_lb6_rr_seq or cilium_lb4_rr_seq bpf maps.
func updateServiceWeightsV2(key *Service4KeyV2, value *RRSeqValue) error {
	if _, err := key.RRMap().OpenOrCreate(); err != nil {
		return err
	}

	return key.RRMap().Update(key.ToNetwork(), value)
}

func deleteServiceLockedV2(key *Service4KeyV2) error {
	err := key.Map().Delete(key.ToNetwork())
	if err != nil {
		return err
	}
	return lookupAndDeleteServiceWeightsV2(key)
}

// lookupAndDeleteServiceWeightsV2 deletes entry from cilium_lb6_rr_seq or cilium_lb4_rr_seq
func lookupAndDeleteServiceWeightsV2(key *Service4KeyV2) error {
	_, err := key.RRMap().Lookup(key.ToNetwork())
	if err != nil {
		// Ignore if entry is not found.
		return nil
	}

	return key.RRMap().Delete(key.ToNetwork())
}

func DumpBackendMapsToUserspace() (map[LegacyBackendID]*loadbalancer.LBBackEnd, error) {
	backendValueMap := map[uint16]*Backend4Value{}
	lbBackends := map[LegacyBackendID]*loadbalancer.LBBackEnd{}

	parseBackendEntries := func(key bpf.MapKey, value bpf.MapValue) {
		backendKey := key.(*Backend4Key)
		backendValue := value.(*Backend4Value)
		backendValueMap[backendKey.ID] = backendValue
	}

	if option.Config.EnableIPv4 {
		err := Backend4Map.DumpWithCallback(parseBackendEntries)
		if err != nil {
			return nil, fmt.Errorf("Unable to dump LB4_BACKEND map: %s", err)
		}
	}

	for backendID, backendVal := range backendValueMap {
		ip := backendVal.Address.IP()
		port := backendVal.Port
		weight := uint16(0)
		proto := loadbalancer.NONE
		lbBackend := loadbalancer.NewLBBackEnd(backendID, proto, ip, port, weight)
		lbBackends[backendVal.LegacyBackendID()] = lbBackend
	}

	return lbBackends, nil
}

func DumpServiceMapsToUserspaceV2(includeMasterBackend bool) (loadbalancer.SVCMap, []*loadbalancer.LBSVC, []error) {
	newSVCMap := loadbalancer.SVCMap{}
	newSVCList := []*loadbalancer.LBSVC{}
	errors := []error{}
	idCache := map[string]loadbalancer.ServiceID{}

	backendValueMap := map[uint16]*Backend4Value{}

	parseBackendEntries := func(key bpf.MapKey, value bpf.MapValue) {
		backendKey := key.(*Backend4Key)
		backendValue := value.(*Backend4Value)
		backendValueMap[backendKey.ID] = backendValue
	}

	parseSVCEntries := func(key bpf.MapKey, value bpf.MapValue) {
		svcKey := key.(*Service4KeyV2)
		//It's the frontend service so we don't add this one
		if svcKey.GetSlave() == 0 && !includeMasterBackend {
			return
		}
		svcValue := value.(*Service4ValueV2)

		scopedLog := log.WithFields(logrus.Fields{
			logfields.BPFMapKey:   svcKey,
			logfields.BPFMapValue: svcValue,
		})

		backendID := svcValue.GetBackendID()
		backendValue, found := backendValueMap[backendID]
		if !found {
			// TODO(brb) return an error?
			return
		}

		scopedLog.Debug("parsing service mapping")
		// TODO(brb) use Backend4 instead of ID+Backend4Value
		fe, be := serviceKeynValuenBackendValue2FEnBE(svcKey, svcValue, backendID, backendValue)

		// Build a cache to map frontend IP to service ID. The master
		// service key does not have the service ID set so the cache
		// needs to be built based on backend key entries.
		if k := svcValue.RevNatKey().GetKey(); k != uint16(0) {
			idCache[fe.String()] = loadbalancer.ServiceID(k)
		}

		svc := newSVCMap.AddFEnBE(fe, be, svcKey.GetSlave())
		newSVCList = append(newSVCList, svc)
	}

	mutex.RLock()
	defer mutex.RUnlock()

	if option.Config.EnableIPv4 {
		err := Backend4Map.DumpWithCallback(parseBackendEntries)
		if err != nil {
			errors = append(errors, err)
		}
		err = Service4MapV2.DumpWithCallback(parseSVCEntries)
		if err != nil {
			errors = append(errors, err)
		}
	}

	//if option.Config.EnableIPv6 {
	//	err := Service6Map.DumpWithCallback(parseSVCEntries)
	//	if err != nil {
	//		errors = append(errors, err)
	//	}
	//}

	// serviceKeynValue2FEnBE() cannot fill in the service ID reliably as
	// not all BPF map entries contain the service ID. Do a pass over all
	// parsed entries and fill in the service ID
	for i := range newSVCList {
		newSVCList[i].FE.ID = idCache[newSVCList[i].FE.String()]
	}

	// Do the same for the svcMap
	for key, svc := range newSVCMap {
		svc.FE.ID = idCache[svc.FE.String()]
		newSVCMap[key] = svc
	}

	return newSVCMap, newSVCList, errors
}

func AddBackendIDs(backendIDs map[LegacyBackendID]uint16) {
	cache.addBackendIDs(backendIDs)
}
