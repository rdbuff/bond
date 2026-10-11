//go:build windows

package firewall

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// Bond tunnels IPv4 only. Without this, a connection that has IPv6 (a phone
// tethered over USB typically does) would carry every IPv6-capable site
// (Google, YouTube, speed tests...) outside the tunnel: unbonded and
// unencrypted. BlockIPv6 makes such connections fail immediately, so apps
// fall back to IPv4 and go through Bond. Loopback, link-local and multicast
// stay allowed so local devices keep working. Like the kill switch, the
// filters live in a dynamic WFP session and disappear with the process.

var v6Session uintptr

var multicastV6 = wtFwpV6AddrAndMask{[16]uint8{0xff}, 8}

func BlockIPv6() error {
	if v6Session != 0 {
		return nil
	}
	session, err := createWfpSession()
	if err != nil {
		return wrapErr(err)
	}
	err = runTransaction(session, func(session uintptr) error {
		bo, err := registerBaseObjects(session)
		if err != nil {
			return err
		}
		if err := permitLoopback(session, bo, 13); err != nil {
			return err
		}
		if err := permitLocalV6(session, bo, 12); err != nil {
			return err
		}
		if err := permitDHCPIPv6(session, bo, 12); err != nil {
			return err
		}
		return blockAllV6(session, bo, 0)
	})
	if err != nil {
		fwpmEngineClose0(session)
		return wrapErr(err)
	}
	v6Session = session
	return nil
}

func UnblockIPv6() {
	if v6Session != 0 {
		fwpmEngineClose0(v6Session)
		v6Session = 0
	}
}

// permitLocalV6 allows IPv6 to link-local (fe80::/10) and multicast
// (ff00::/8) addresses, in both directions.
func permitLocalV6(session uintptr, bo *baseObjects, weight uint8) error {
	for _, dst := range []*wtFwpV6AddrAndMask{&linkLocal, &multicastV6} {
		condition := wtFwpmFilterCondition0{
			fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_V6_ADDR_MASK,
				value: uintptr(unsafe.Pointer(dst)),
			},
		}
		for _, layer := range []windows.GUID{cFWPM_LAYER_ALE_AUTH_CONNECT_V6, cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6} {
			displayData, err := createWtFwpmDisplayData0("Permit local IPv6", "")
			if err != nil {
				return wrapErr(err)
			}
			filter := wtFwpmFilter0{
				displayData:         *displayData,
				providerKey:         &bo.provider,
				layerKey:            layer,
				subLayerKey:         bo.filters,
				weight:              filterWeight(weight),
				numFilterConditions: 1,
				filterCondition:     &condition,
				action:              wtFwpmAction0{_type: cFWP_ACTION_PERMIT},
			}
			filterID := uint64(0)
			if err := fwpmFilterAdd0(session, &filter, 0, &filterID); err != nil {
				return wrapErr(err)
			}
		}
	}
	return nil
}

func blockAllV6(session uintptr, bo *baseObjects, weight uint8) error {
	for _, layer := range []windows.GUID{cFWPM_LAYER_ALE_AUTH_CONNECT_V6, cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6} {
		displayData, err := createWtFwpmDisplayData0("Block IPv6 outside the Bond tunnel", "")
		if err != nil {
			return wrapErr(err)
		}
		filter := wtFwpmFilter0{
			displayData: *displayData,
			providerKey: &bo.provider,
			layerKey:    layer,
			subLayerKey: bo.filters,
			weight:      filterWeight(weight),
			action:      wtFwpmAction0{_type: cFWP_ACTION_BLOCK},
		}
		filterID := uint64(0)
		if err := fwpmFilterAdd0(session, &filter, 0, &filterID); err != nil {
			return wrapErr(err)
		}
	}
	return nil
}
