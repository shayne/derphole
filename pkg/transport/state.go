package transport

import "time"

// Path describes the currently selected transport path.
type Path int

const (
	PathUnknown Path = iota
	PathRelay
	PathDirect
)

type pathState struct {
	current        Path
	directPossible bool
	directBroken   bool
	fallbackReason string
	changedAt      time.Time
}

func newPathState(hasRelay, hasDirect bool) pathState {
	current := PathUnknown
	if hasRelay {
		current = PathRelay
	}

	return pathState{
		current:        current,
		directPossible: hasDirect,
		changedAt:      time.Now(),
	}
}

func (s pathState) path() Path {
	return s.current
}

func (s *pathState) markDirectReady() bool {
	if !s.directPossible || s.directBroken || s.current == PathDirect {
		return false
	}
	s.current = PathDirect
	s.fallbackReason = ""
	s.changedAt = time.Now()
	return true
}

func (s *pathState) markDirectBroken(reason string) bool {
	changed := s.current != PathRelay || !s.directBroken || s.fallbackReason != reason
	s.directBroken = true
	if s.current != PathUnknown {
		s.current = PathRelay
	}
	s.fallbackReason = reason
	s.changedAt = time.Now()
	return changed
}
