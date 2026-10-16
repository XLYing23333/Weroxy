package weroxy

import (
	"time"
	"weroxy/server/internal/ports"
)

type scaleObservation struct {
	high, low, changed time.Time
	reason             string
}

// AdaptiveAssignments observes business session pressure, not bandwidth. It
// grows by one after ten seconds of sustained pressure and shrinks by one
// after a minute idle, with a thirty-second change cooldown.
func (s *Service) AdaptiveAssignments(desired []Forward, assignments []ports.Assignment, pool ports.Pool) []ports.Assignment {
	now := time.Now()
	s.mu.Lock()
	if s.scaling == nil {
		s.scaling = map[int64]scaleObservation{}
	}
	pressure := map[int64]int{}
	busy := map[[2]int64]bool{}
	for _, sess := range s.sessions {
		if sess.finished.Load() {
			continue
		}
		weight := 1
		if !sess.ready {
			weight = 2
		}
		pressure[sess.forwardID] += weight
		busy[[2]int64{sess.forwardID, int64(sess.port)}] = true
	}
	current := map[int64]int{}
	clean := make([]ports.Assignment, 0, len(assignments))
	changed := false
	for _, item := range assignments {
		if item.State == ports.Draining && !busy[[2]int64{item.ForwardID, int64(item.Port)}] {
			changed = true
			continue
		}
		if item.State == ports.Serving {
			current[item.ForwardID]++
		}
		clean = append(clean, item)
	}
	specs := make([]ports.Spec, 0, len(desired))
	seen := map[int64]bool{}
	for _, f := range desired {
		seen[f.ID] = true
		target := current[f.ID]
		if target < f.Min {
			target = f.Preferred
		}
		observation := s.scaling[f.ID]
		if pressure[f.ID] >= target*8 && target < f.Max && f.Enabled {
			if observation.high.IsZero() {
				observation.high = now
			}
			observation.low = time.Time{}
			if now.Sub(observation.high) >= 10*time.Second && now.Sub(observation.changed) >= 30*time.Second {
				target++
				observation.reason = "scale_up_requested"
				observation.changed = now
				observation.high = time.Time{}
				changed = true
			}
		} else if pressure[f.ID] == 0 && target > f.Min && f.Enabled {
			if observation.low.IsZero() {
				observation.low = now
			}
			observation.high = time.Time{}
			if now.Sub(observation.low) >= time.Minute && now.Sub(observation.changed) >= 30*time.Second {
				target--
				observation.reason = "scale_down_requested"
				observation.changed = now
				observation.low = time.Time{}
				changed = true
			}
		} else {
			observation.high = time.Time{}
			observation.low = time.Time{}
		}
		s.scaling[f.ID] = observation
		specs = append(specs, ports.Spec{ID: f.ID, DeviceID: f.DeviceID, Mode: f.Mode, Min: f.Min, Preferred: target, Max: f.Max, DeviceMax: f.DeviceMax, Enabled: f.Enabled, UseReserved: f.UseReserved, ManualPorts: f.ManualPorts})
	}
	for id := range s.scaling {
		if !seen[id] {
			delete(s.scaling, id)
		}
	}
	s.mu.Unlock()
	if !changed {
		return assignments
	}
	candidates := pool
	candidates.Unavailable = map[int]bool{}
	for port, value := range pool.Unavailable {
		candidates.Unavailable[port] = value
	}
	for _, item := range clean {
		if item.State == ports.Draining {
			candidates.Unavailable[item.Port] = true
		}
	}
	out := ports.Allocate(candidates, specs)
	if len(out.Rejected) != 0 {
		s.recordScalingFailure(out.Rejected)
		return clean
	}
	// A busy binding removed by this decision cannot be immediately reused
	// as someone else's exclusive candidate while its old stream drains.
	removedBusy := false
	selected := map[[2]int64]bool{}
	for _, item := range out.Assignments {
		selected[[2]int64{item.ForwardID, int64(item.Port)}] = true
	}
	for _, item := range clean {
		key := [2]int64{item.ForwardID, int64(item.Port)}
		if busy[key] && !selected[key] {
			candidates.Unavailable[item.Port] = true
			removedBusy = true
		}
	}
	if removedBusy {
		out = ports.Allocate(candidates, specs)
		if len(out.Rejected) != 0 {
			s.recordScalingFailure(out.Rejected)
			return clean
		}
	}
	have := map[[2]int64]bool{}
	for _, item := range out.Assignments {
		have[[2]int64{item.ForwardID, int64(item.Port)}] = true
	}
	for _, item := range clean {
		key := [2]int64{item.ForwardID, int64(item.Port)}
		if !have[key] && busy[key] {
			item.State = ports.Draining
			out.Assignments = append(out.Assignments, item)
		}
	}
	return out.Assignments
}

func (s *Service) recordScalingFailure(rejected map[int64]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range rejected {
		observation := s.scaling[id]
		observation.reason = "scale_candidate_shortage"
		s.scaling[id] = observation
	}
}
