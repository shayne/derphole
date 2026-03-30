package transport

// Path describes the currently selected transport path.
type Path int

const (
	PathUnknown Path = iota
	PathRelay
	PathDirect
)

type pathState struct {
	current           Path
	relayConfigured   bool
	directConfigured  bool
	directUnavailable bool
}

func newPathState(hasRelay, hasDirect bool) pathState {
	current := PathUnknown
	if hasRelay {
		current = PathRelay
	}

	return pathState{
		current:          current,
		relayConfigured:  hasRelay,
		directConfigured: hasDirect,
	}
}

func (s pathState) path() Path {
	return s.current
}

func (s *pathState) activateConfiguredDirect() bool {
	if !s.directConfigured || s.directUnavailable || s.current == PathDirect {
		return false
	}
	s.current = PathDirect
	return true
}

func (s *pathState) markDirectBroken() bool {
	next := PathUnknown
	if s.relayConfigured {
		next = PathRelay
	}

	changed := s.current != next || !s.directUnavailable
	s.directUnavailable = true
	s.current = next
	return changed
}
