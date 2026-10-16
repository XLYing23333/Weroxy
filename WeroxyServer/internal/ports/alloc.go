package ports

import "sort"

const (
	// Shared lets forwards reuse the same data ports.
	Shared = "shared"
	// Exclusive gives a forward ports that nobody else can use.
	Exclusive = "exclusive"
	// Serving accepts new sessions.
	Serving = "serving"
	// Draining keeps existing sessions and refuses new ones.
	Draining = "draining"

	// ReasonDeviceQuota means the device's distinct data-port union is exhausted.
	ReasonDeviceQuota = "device_port_quota"
	// ReasonGlobalQuota means the usable data pool has no room.
	ReasonGlobalQuota = "global_port_quota"
	// ReasonExclusive means an exclusive forward could not get its minimum.
	ReasonExclusive = "exclusive_conflict"
	// ReasonBelowMin means the forward's minimum could not be met.
	ReasonBelowMin = "below_min"
	// ReasonRange means min, preferred, and max are not ordered.
	ReasonRange = "port_range"
)

// Pool is an inclusive data-port range. The last Reserved ports are not
// available to ordinary allocation.
type Pool struct {
	First    int
	Last     int
	Reserved int
	// Unavailable removes failed automatic candidates without moving the reserved tail.
	Unavailable map[int]bool
}

// Spec is one forward's data-port request.
type Spec struct {
	ID          int64
	DeviceID    int64
	Mode        string
	Min         int
	Preferred   int
	Max         int
	DeviceMax   int
	Enabled     bool
	UseReserved bool
	// Unavailable is specific to this device/Forward; it does not disable a shared port globally.
	Unavailable map[int]bool
	ManualPorts []int
}

// Assignment binds one data port to one forward.
type Assignment struct {
	ForwardID int64
	DeviceID  int64
	Port      int
	State     string
}

// View is the capacity snapshot for one forward.
type View struct {
	ForwardID         int64
	ConfiguredMax     int
	Current           int
	Draining          int
	AvailableMaxTotal int
	CanGrowBy         int
	Reasons           []string
	Legacy            bool
}

// Outcome is one allocation pass.
type Outcome struct {
	Assignments []Assignment
	Rejected    map[int64]string
	Views       map[int64]View
}

// Usable returns the ordinary ports, excluding the reserved tail.
func (p Pool) Usable() []int {
	if p.Last < p.First || p.Reserved < 0 {
		return nil
	}
	last := p.Last - p.Reserved
	if last < p.First {
		return nil
	}
	out := make([]int, 0, last-p.First+1)
	for port := p.First; port <= last; port++ {
		if !p.Unavailable[port] {
			out = append(out, port)
		}
	}
	return out
}

// ReservedPorts is the tail ordinary allocation must leave untouched.
func (p Pool) ReservedPorts() []int {
	if p.Reserved <= 0 || p.Last < p.First {
		return nil
	}
	start := p.Last - p.Reserved + 1
	if start < p.First {
		start = p.First
	}
	out := make([]int, 0, p.Last-start+1)
	for port := start; port <= p.Last; port++ {
		if !p.Unavailable[port] {
			out = append(out, port)
		}
	}
	return out
}

// ValidRange reports whether 1 ≤ min ≤ preferred ≤ max.
func ValidRange(min, preferred, max int) bool {
	return min >= 1 && min <= preferred && preferred <= max && max <= 65535
}

// Allocate assigns data ports. Shared forwards reuse one small set.
// An exclusive forward that cannot reach its minimum is rejected and gets none.
func Allocate(pool Pool, specs []Spec) Outcome {
	out := Outcome{Rejected: map[int64]string{}, Views: map[int64]View{}}
	usable := pool.Usable()
	var shared, exclusive []Spec
	for _, spec := range specs {
		if !spec.Enabled {
			continue
		}
		if !ValidRange(spec.Min, spec.Preferred, spec.Max) {
			out.Rejected[spec.ID] = ReasonRange
			continue
		}
		if spec.Mode == Exclusive {
			exclusive = append(exclusive, spec)
			continue
		}
		shared = append(shared, spec)
	}
	shared = fairOrder(shared)
	exclusive = fairOrder(exclusive)
	reservedFree := pool.ReservedPorts()
	used := map[int]bool{}
	devicePorts := map[int64]map[int]struct{}{}
	note := func(deviceID int64, port int) {
		set := devicePorts[deviceID]
		if set == nil {
			set = map[int]struct{}{}
			devicePorts[deviceID] = set
		}
		set[port] = struct{}{}
	}
	held := func(deviceID int64, port int) bool {
		_, ok := devicePorts[deviceID][port]
		return ok
	}
	for _, spec := range shared {
		want := spec.Preferred
		if want > spec.Max {
			want = spec.Max
		}
		candidates := usable
		if spec.UseReserved {
			candidates = append(append([]int{}, usable...), reservedFree...)
		}
		got, limited := take(spec, candidates, want, devicePorts, held, true)
		if len(got) < spec.Min {
			out.Rejected[spec.ID] = rejectReason(limited, false)
			continue
		}
		reservedFree = subtract(reservedFree, got)
		for _, port := range got {
			used[port] = true
			out.Assignments = append(out.Assignments, Assignment{ForwardID: spec.ID, DeviceID: spec.DeviceID, Port: port, State: Serving})
			note(spec.DeviceID, port)
		}
	}
	var free []int
	for _, port := range usable {
		if !used[port] {
			free = append(free, port)
		}
	}
	// Establish each exclusive minimum before spending remaining ports on
	// preferred capacity. A device with several forwards gets one turn per
	// round instead of consuming the pool before another device is considered.
	allocated := map[int64]int{}
	accepted := map[int64]bool{}
	assign := func(spec Spec, got []int) {
		free = subtract(free, got)
		reservedFree = subtract(reservedFree, got)
		for _, port := range got {
			used[port] = true
			out.Assignments = append(out.Assignments, Assignment{ForwardID: spec.ID, DeviceID: spec.DeviceID, Port: port, State: Serving})
			note(spec.DeviceID, port)
		}
		allocated[spec.ID] += len(got)
	}
	for _, spec := range exclusive {
		candidates := free
		if spec.UseReserved {
			candidates = append(append([]int{}, free...), reservedFree...)
		}
		got, limited := take(spec, candidates, spec.Min, devicePorts, held, false)
		if len(got) < spec.Min {
			out.Rejected[spec.ID] = rejectReason(limited, true)
			continue
		}
		accepted[spec.ID] = true
		assign(spec, got)
	}
	for {
		progress := false
		for _, spec := range exclusive {
			if !accepted[spec.ID] || allocated[spec.ID] >= spec.Preferred {
				continue
			}
			candidates := free
			if spec.UseReserved {
				candidates = append(append([]int{}, free...), reservedFree...)
			}
			got, _ := take(spec, candidates, 1, devicePorts, held, false)
			if len(got) == 0 {
				continue
			}
			assign(spec, got)
			progress = true
		}
		if !progress {
			break
		}
	}

	out.Views = explain(pool, specs, out)
	return out
}

// fairOrder interleaves forwards by device in stable rounds. It is used for
// allocation decisions, never to reorder the caller's configuration.
func fairOrder(specs []Spec) []Spec {
	byDevice := map[int64][]Spec{}
	var devices []int64
	for _, spec := range specs {
		if _, exists := byDevice[spec.DeviceID]; !exists {
			devices = append(devices, spec.DeviceID)
		}
		byDevice[spec.DeviceID] = append(byDevice[spec.DeviceID], spec)
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i] < devices[j] })
	for _, id := range devices {
		sort.Slice(byDevice[id], func(i, j int) bool { return byDevice[id][i].ID < byDevice[id][j].ID })
	}
	out := make([]Spec, 0, len(specs))
	for round := 0; len(out) < len(specs); round++ {
		for _, id := range devices {
			if round < len(byDevice[id]) {
				out = append(out, byDevice[id][round])
			}
		}
	}
	return out
}

func take(spec Spec, candidates []int, want int, devicePorts map[int64]map[int]struct{}, held func(int64, int) bool, reuse bool) ([]int, bool) {
	var got []int
	limited := false
	for _, port := range candidates {
		if !spec.Allows(port) {
			continue
		}
		if len(got) >= want {
			break
		}
		if reuse && held(spec.DeviceID, port) {
			got = append(got, port)
			continue
		}
		union := len(devicePorts[spec.DeviceID]) + newPorts(got, devicePorts[spec.DeviceID])
		if spec.DeviceMax > 0 && union >= spec.DeviceMax {
			limited = true
			continue
		}
		got = append(got, port)
	}
	return got, limited
}

func newPorts(got []int, have map[int]struct{}) int {
	n := 0
	for _, port := range got {
		if _, ok := have[port]; !ok {
			n++
		}
	}
	return n
}

func subtract(ports, drop []int) []int {
	skip := map[int]bool{}
	for _, port := range drop {
		skip[port] = true
	}
	var out []int
	for _, port := range ports {
		if !skip[port] {
			out = append(out, port)
		}
	}
	return out
}

func rejectReason(deviceLimited, exclusive bool) string {
	if deviceLimited {
		return ReasonDeviceQuota
	}
	if exclusive {
		return ReasonExclusive
	}
	return ReasonBelowMin
}

func explain(pool Pool, specs []Spec, out Outcome) map[int64]View {
	views := map[int64]View{}
	usable := pool.Usable()
	used := map[int]struct{}{}
	for _, item := range out.Assignments {
		used[item.Port] = struct{}{}
	}
	byForward := map[int64][]Assignment{}
	for _, item := range out.Assignments {
		byForward[item.ForwardID] = append(byForward[item.ForwardID], item)
	}
	deviceUnion := map[int64]map[int]struct{}{}
	for _, item := range out.Assignments {
		if item.State != Serving {
			continue
		}
		set := deviceUnion[item.DeviceID]
		if set == nil {
			set = map[int]struct{}{}
			deviceUnion[item.DeviceID] = set
		}
		set[item.Port] = struct{}{}
	}
	sharedOpen := map[int]struct{}{}
	for _, spec := range specs {
		if spec.Mode == Exclusive {
			continue
		}
		for _, item := range byForward[spec.ID] {
			if item.State == Serving {
				sharedOpen[item.Port] = struct{}{}
			}
		}
	}
	for _, spec := range specs {
		if !spec.Enabled {
			continue
		}
		view := View{ForwardID: spec.ID, ConfiguredMax: spec.Max}
		for _, item := range byForward[spec.ID] {
			if item.State == Draining {
				view.Draining++
				continue
			}
			view.Current++
		}
		if reason, rejected := out.Rejected[spec.ID]; rejected {
			view.Reasons = []string{reason}
			views[spec.ID] = view
			continue
		}
		room := spec.Max - view.Current
		var reasons []string
		join := 0
		if spec.Mode != Exclusive {
			for port := range sharedOpen {
				if !spec.Allows(port) {
					continue
				}
				mine := false
				for _, item := range byForward[spec.ID] {
					if item.Port == port && item.State == Serving {
						mine = true
					}
				}
				if !mine {
					join++
				}
			}
		}
		free := 0
		for _, port := range usable {
			if _, taken := used[port]; !taken && spec.Allows(port) {
				free++
			}
		}
		grow := free + join
		if spec.DeviceMax > 0 {
			left := spec.DeviceMax - len(deviceUnion[spec.DeviceID])
			if left < grow {
				grow = left
				reasons = append(reasons, ReasonDeviceQuota)
			}
		}
		if free < grow && spec.Mode == Exclusive {
			reasons = append(reasons, ReasonExclusive)
		}
		if grow > room {
			grow = room
		}
		if grow < 0 {
			grow = 0
		}
		if grow < spec.Max-view.Current && free+join < spec.Max-view.Current && !contains(reasons, ReasonDeviceQuota) {
			reasons = append(reasons, ReasonGlobalQuota)
		}
		view.CanGrowBy = grow
		view.AvailableMaxTotal = view.Current + grow
		view.Reasons = reasons
		views[spec.ID] = view
	}
	return views
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// Preview describes one capacity snapshot from assignments that already exist.
func Preview(pool Pool, specs []Spec, assignments []Assignment) map[int64]View {
	out := Outcome{Assignments: assignments, Rejected: map[int64]string{}}
	return explain(pool, specs, out)
}

// MarkDrain keeps the lowest max serving ports and drains the rest.
func MarkDrain(items []Assignment, forwardID int64, max int) []Assignment {
	if max < 0 {
		max = 0
	}
	out := make([]Assignment, len(items))
	copy(out, items)
	indexes := make([]int, 0)
	for i := range out {
		if out[i].ForwardID == forwardID && out[i].State == Serving {
			indexes = append(indexes, i)
		}
	}
	for i := 0; i < len(indexes); i++ {
		for j := i + 1; j < len(indexes); j++ {
			if out[indexes[j]].Port < out[indexes[i]].Port {
				indexes[i], indexes[j] = indexes[j], indexes[i]
			}
		}
	}
	for n, index := range indexes {
		if n >= max {
			out[index].State = Draining
		}
	}
	return out
}

// Allows combines operator-selected candidates with per-device observations.
func (s Spec) Allows(port int) bool {
	if s.Unavailable[port] {
		return false
	}
	if len(s.ManualPorts) == 0 {
		return true
	}
	for _, selected := range s.ManualPorts {
		if selected == port {
			return true
		}
	}
	return false
}

// Explain evaluates actual bindings against the current eligible pool.
func Explain(pool Pool, specs []Spec, assignments []Assignment) map[int64]View {
	return explain(pool, specs, Outcome{Assignments: assignments, Rejected: map[int64]string{}})
}
