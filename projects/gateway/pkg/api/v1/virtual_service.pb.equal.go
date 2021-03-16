// Code generated by protoc-gen-ext. DO NOT EDIT.
// source: github.com/solo-io/gloo/projects/gateway/api/v1/virtual_service.proto

package v1

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/golang/protobuf/proto"
	equality "github.com/solo-io/protoc-gen-ext/pkg/equality"
)

// ensure the imports are used
var (
	_ = errors.New("")
	_ = fmt.Print
	_ = binary.LittleEndian
	_ = bytes.Compare
	_ = strings.Compare
	_ = equality.Equalizer(nil)
	_ = proto.Message(nil)
)

// Equal function
func (m *VirtualService) Equal(that interface{}) bool {
	if that == nil {
		return m == nil
	}

	target, ok := that.(*VirtualService)
	if !ok {
		that2, ok := that.(VirtualService)
		if ok {
			target = &that2
		} else {
			return false
		}
	}
	if target == nil {
		return m == nil
	} else if m == nil {
		return false
	}

	if h, ok := interface{}(m.GetVirtualHost()).(equality.Equalizer); ok {
		if !h.Equal(target.GetVirtualHost()) {
			return false
		}
	} else {
		if !proto.Equal(m.GetVirtualHost(), target.GetVirtualHost()) {
			return false
		}
	}

	if h, ok := interface{}(m.GetSslConfig()).(equality.Equalizer); ok {
		if !h.Equal(target.GetSslConfig()) {
			return false
		}
	} else {
		if !proto.Equal(m.GetSslConfig(), target.GetSslConfig()) {
			return false
		}
	}

	if strings.Compare(m.GetDisplayName(), target.GetDisplayName()) != 0 {
		return false
	}

	if h, ok := interface{}(m.GetStatus()).(equality.Equalizer); ok {
		if !h.Equal(target.GetStatus()) {
			return false
		}
	} else {
		if !proto.Equal(m.GetStatus(), target.GetStatus()) {
			return false
		}
	}

	if h, ok := interface{}(m.GetMetadata()).(equality.Equalizer); ok {
		if !h.Equal(target.GetMetadata()) {
			return false
		}
	} else {
		if !proto.Equal(m.GetMetadata(), target.GetMetadata()) {
			return false
		}
	}

	return true
}

// Equal function
func (m *VirtualHost) Equal(that interface{}) bool {
	if that == nil {
		return m == nil
	}

	target, ok := that.(*VirtualHost)
	if !ok {
		that2, ok := that.(VirtualHost)
		if ok {
			target = &that2
		} else {
			return false
		}
	}
	if target == nil {
		return m == nil
	} else if m == nil {
		return false
	}

	if len(m.GetDomains()) != len(target.GetDomains()) {
		return false
	}
	for idx, v := range m.GetDomains() {

		if strings.Compare(v, target.GetDomains()[idx]) != 0 {
			return false
		}

	}

	if len(m.GetRoutes()) != len(target.GetRoutes()) {
		return false
	}
	for idx, v := range m.GetRoutes() {

		if h, ok := interface{}(v).(equality.Equalizer); ok {
			if !h.Equal(target.GetRoutes()[idx]) {
				return false
			}
		} else {
			if !proto.Equal(v, target.GetRoutes()[idx]) {
				return false
			}
		}

	}

	if h, ok := interface{}(m.GetOptions()).(equality.Equalizer); ok {
		if !h.Equal(target.GetOptions()) {
			return false
		}
	} else {
		if !proto.Equal(m.GetOptions(), target.GetOptions()) {
			return false
		}
	}

	return true
}

// Equal function
func (m *Route) Equal(that interface{}) bool {
	if that == nil {
		return m == nil
	}

	target, ok := that.(*Route)
	if !ok {
		that2, ok := that.(Route)
		if ok {
			target = &that2
		} else {
			return false
		}
	}
	if target == nil {
		return m == nil
	} else if m == nil {
		return false
	}

	if len(m.GetMatchers()) != len(target.GetMatchers()) {
		return false
	}
	for idx, v := range m.GetMatchers() {

		if h, ok := interface{}(v).(equality.Equalizer); ok {
			if !h.Equal(target.GetMatchers()[idx]) {
				return false
			}
		} else {
			if !proto.Equal(v, target.GetMatchers()[idx]) {
				return false
			}
		}

	}

	if h, ok := interface{}(m.GetInheritableMatchers()).(equality.Equalizer); ok {
		if !h.Equal(target.GetInheritableMatchers()) {
			return false
		}
	} else {
		if !proto.Equal(m.GetInheritableMatchers(), target.GetInheritableMatchers()) {
			return false
		}
	}

	if h, ok := interface{}(m.GetInheritablePathMatchers()).(equality.Equalizer); ok {
		if !h.Equal(target.GetInheritablePathMatchers()) {
			return false
		}
	} else {
		if !proto.Equal(m.GetInheritablePathMatchers(), target.GetInheritablePathMatchers()) {
			return false
		}
	}

	if h, ok := interface{}(m.GetOptions()).(equality.Equalizer); ok {
		if !h.Equal(target.GetOptions()) {
			return false
		}
	} else {
		if !proto.Equal(m.GetOptions(), target.GetOptions()) {
			return false
		}
	}

	if strings.Compare(m.GetName(), target.GetName()) != 0 {
		return false
	}

	if h, ok := interface{}(m.GetRuntimeFraction()).(equality.Equalizer); ok {
		if !h.Equal(target.GetRuntimeFraction()) {
			return false
		}
	} else {
		if !proto.Equal(m.GetRuntimeFraction(), target.GetRuntimeFraction()) {
			return false
		}
	}

	switch m.Action.(type) {

	case *Route_RouteAction:

		if h, ok := interface{}(m.GetRouteAction()).(equality.Equalizer); ok {
			if !h.Equal(target.GetRouteAction()) {
				return false
			}
		} else {
			if !proto.Equal(m.GetRouteAction(), target.GetRouteAction()) {
				return false
			}
		}

	case *Route_RedirectAction:

		if h, ok := interface{}(m.GetRedirectAction()).(equality.Equalizer); ok {
			if !h.Equal(target.GetRedirectAction()) {
				return false
			}
		} else {
			if !proto.Equal(m.GetRedirectAction(), target.GetRedirectAction()) {
				return false
			}
		}

	case *Route_DirectResponseAction:

		if h, ok := interface{}(m.GetDirectResponseAction()).(equality.Equalizer); ok {
			if !h.Equal(target.GetDirectResponseAction()) {
				return false
			}
		} else {
			if !proto.Equal(m.GetDirectResponseAction(), target.GetDirectResponseAction()) {
				return false
			}
		}

	case *Route_DelegateAction:

		if h, ok := interface{}(m.GetDelegateAction()).(equality.Equalizer); ok {
			if !h.Equal(target.GetDelegateAction()) {
				return false
			}
		} else {
			if !proto.Equal(m.GetDelegateAction(), target.GetDelegateAction()) {
				return false
			}
		}

	}

	return true
}

// Equal function
func (m *DelegateAction) Equal(that interface{}) bool {
	if that == nil {
		return m == nil
	}

	target, ok := that.(*DelegateAction)
	if !ok {
		that2, ok := that.(DelegateAction)
		if ok {
			target = &that2
		} else {
			return false
		}
	}
	if target == nil {
		return m == nil
	} else if m == nil {
		return false
	}

	if strings.Compare(m.GetName(), target.GetName()) != 0 {
		return false
	}

	if strings.Compare(m.GetNamespace(), target.GetNamespace()) != 0 {
		return false
	}

	switch m.DelegationType.(type) {

	case *DelegateAction_Ref:

		if h, ok := interface{}(m.GetRef()).(equality.Equalizer); ok {
			if !h.Equal(target.GetRef()) {
				return false
			}
		} else {
			if !proto.Equal(m.GetRef(), target.GetRef()) {
				return false
			}
		}

	case *DelegateAction_Selector:

		if h, ok := interface{}(m.GetSelector()).(equality.Equalizer); ok {
			if !h.Equal(target.GetSelector()) {
				return false
			}
		} else {
			if !proto.Equal(m.GetSelector(), target.GetSelector()) {
				return false
			}
		}

	}

	return true
}

// Equal function
func (m *RouteTableSelector) Equal(that interface{}) bool {
	if that == nil {
		return m == nil
	}

	target, ok := that.(*RouteTableSelector)
	if !ok {
		that2, ok := that.(RouteTableSelector)
		if ok {
			target = &that2
		} else {
			return false
		}
	}
	if target == nil {
		return m == nil
	} else if m == nil {
		return false
	}

	if len(m.GetNamespaces()) != len(target.GetNamespaces()) {
		return false
	}
	for idx, v := range m.GetNamespaces() {

		if strings.Compare(v, target.GetNamespaces()[idx]) != 0 {
			return false
		}

	}

	if len(m.GetLabels()) != len(target.GetLabels()) {
		return false
	}
	for k, v := range m.GetLabels() {

		if strings.Compare(v, target.GetLabels()[k]) != 0 {
			return false
		}

	}

	if len(m.GetExpressions()) != len(target.GetExpressions()) {
		return false
	}
	for idx, v := range m.GetExpressions() {

		if h, ok := interface{}(v).(equality.Equalizer); ok {
			if !h.Equal(target.GetExpressions()[idx]) {
				return false
			}
		} else {
			if !proto.Equal(v, target.GetExpressions()[idx]) {
				return false
			}
		}

	}

	return true
}

// Equal function
func (m *RouteTableSelector_Expression) Equal(that interface{}) bool {
	if that == nil {
		return m == nil
	}

	target, ok := that.(*RouteTableSelector_Expression)
	if !ok {
		that2, ok := that.(RouteTableSelector_Expression)
		if ok {
			target = &that2
		} else {
			return false
		}
	}
	if target == nil {
		return m == nil
	} else if m == nil {
		return false
	}

	if strings.Compare(m.GetKey(), target.GetKey()) != 0 {
		return false
	}

	if m.GetOperator() != target.GetOperator() {
		return false
	}

	if len(m.GetValues()) != len(target.GetValues()) {
		return false
	}
	for idx, v := range m.GetValues() {

		if strings.Compare(v, target.GetValues()[idx]) != 0 {
			return false
		}

	}

	return true
}
