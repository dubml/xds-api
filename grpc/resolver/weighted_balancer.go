package resolver

import (
	"sync/atomic"

	runtimetelemetry "github.com/dubml/xds-api/grpc/telemetry"
	"google.golang.org/grpc/balancer"
	"google.golang.org/grpc/balancer/base"
)

// weightedBalancerName is the ServiceConfig load-balancing policy name.
const weightedBalancerName = "xds_weighted"

// weightAttrKey is the resolver.Address.Attributes key for normalised weight.
type weightAttrKey struct{}

func init() {
	balancer.Register(base.NewBalancerBuilder(
		weightedBalancerName,
		&weightedPickerBuilder{},
		base.Config{},
	))
}

type weightedPickerBuilder struct{}

type wSlot struct {
	sc balancer.SubConn
}

func (pb *weightedPickerBuilder) Build(info base.PickerBuildInfo) balancer.Picker {
	if len(info.ReadySCs) == 0 {
		return base.NewErrPicker(balancer.ErrNoSubConnAvailable)
	}

	var slots []wSlot
	for sc, sci := range info.ReadySCs {
		w := uint32(1)
		if sci.Address.Attributes != nil {
			if v := sci.Address.Attributes.Value(weightAttrKey{}); v != nil {
				if ww, ok := v.(uint32); ok && ww > 0 {
					w = ww
				}
			}
		}
		for i := uint32(0); i < w; i++ {
			slots = append(slots, wSlot{sc: sc})
		}
	}

	if len(slots) == 0 {
		return base.NewErrPicker(balancer.ErrNoSubConnAvailable)
	}

	return &weightedPicker{slots: slots}
}

type weightedPicker struct {
	slots []wSlot
	next  uint64
}

func (p *weightedPicker) Pick(info balancer.PickInfo) (balancer.PickResult, error) {
	idx := atomic.AddUint64(&p.next, 1) - 1
	return balancer.PickResult{
		SubConn: p.slots[idx%uint64(len(p.slots))].sc,
		Done: func(done balancer.DoneInfo) {
			if !runtimetelemetry.UsesNativeStats(info.Ctx) {
				runtimetelemetry.Default().RecordClient(info.FullMethodName, done.Err)
			}
		},
	}, nil
}
