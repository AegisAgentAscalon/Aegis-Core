package devicelink

import (
	"context"
	"reflect"
	"sync"
	"testing"
)

func TestMemoryDiscoveryOwnsPublishedAndReturnedRecords(t *testing.T) {
	ctx := context.Background()
	p := NewMemoryDiscoveryProvider()
	original := PresenceRecord{DeviceID: "device", Capabilities: []string{"initial"}, EndpointHints: []EndpointHint{{Address: "initial"}}, ResourcesSummary: []ResourceSummary{{Count: 1}}}
	input := clonePresenceRecord(original)
	if err := p.Publish(ctx, input); err != nil {
		t.Fatal(err)
	}
	mutate := func(r PresenceRecord) {
		r.Capabilities[0] = "changed"
		r.EndpointHints[0].Address = "changed"
		r.ResourcesSummary[0].Count = 9
	}
	mutate(input)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			found, err := p.Discover(ctx)
			if err != nil || len(found) != 1 {
				t.Errorf("discover: %v %v", found, err)
				return
			}
			if !reflect.DeepEqual(found[0], original) {
				t.Error("SD-08: discovery storage aliases caller data")
			}
			mutate(found[0])
		}()
	}
	wg.Wait()
	found, err := p.Discover(ctx)
	if err != nil || len(found) != 1 || !reflect.DeepEqual(found[0], original) {
		t.Fatalf("output mutation reached storage: %v %v", found, err)
	}
}
