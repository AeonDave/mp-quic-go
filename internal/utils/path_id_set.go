package utils

import (
	"slices"

	"github.com/AeonDave/mp-quic-go/internal/protocol"
)

// A PathIDSet is a set of path IDs.
// It stores ranges of consecutive path IDs, so it stays small if the path IDs in the set are (mostly) consecutive.
// This is the case for the path IDs that were closed on a connection using IETF Multipath QUIC:
// path IDs are never reused, and are used in (roughly) ascending order.
type PathIDSet struct {
	ranges []pathIDRange // sorted, neither overlapping nor adjacent
}

// a range of path IDs, both start and end are included
type pathIDRange struct {
	start, end protocol.PathID
}

// Add adds a path ID to the set.
func (s *PathIDSet) Add(id protocol.PathID) {
	// the index of the first range that ends at or after id
	i, _ := slices.BinarySearchFunc(s.ranges, id, func(r pathIDRange, id protocol.PathID) int {
		switch {
		case r.end < id:
			return -1
		case r.end > id:
			return 1
		default:
			return 0
		}
	})
	if i < len(s.ranges) && s.ranges[i].start <= id {
		return // already contained
	}
	extendsPrev := i > 0 && s.ranges[i-1].end+1 == id
	extendsNext := i < len(s.ranges) && s.ranges[i].start == id+1
	switch {
	case extendsPrev && extendsNext:
		s.ranges[i-1].end = s.ranges[i].end
		s.ranges = slices.Delete(s.ranges, i, i+1)
	case extendsPrev:
		s.ranges[i-1].end = id
	case extendsNext:
		s.ranges[i].start = id
	default:
		s.ranges = slices.Insert(s.ranges, i, pathIDRange{start: id, end: id})
	}
}

// Contains says if a path ID is contained in the set.
func (s *PathIDSet) Contains(id protocol.PathID) bool {
	_, found := slices.BinarySearchFunc(s.ranges, id, func(r pathIDRange, id protocol.PathID) int {
		switch {
		case r.end < id:
			return -1
		case r.start > id:
			return 1
		default:
			return 0
		}
	})
	return found
}

// Len returns the number of path IDs in the set.
func (s *PathIDSet) Len() int {
	var n int
	for _, r := range s.ranges {
		n += int(r.end-r.start) + 1
	}
	return n
}
