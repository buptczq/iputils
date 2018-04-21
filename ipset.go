package iputils

import (
	"errors"
	"net"
	"unsafe"
)

// Radix tree node
type node struct {
	left   *node
	right  *node
	parent *node
	value  interface{}
}

type IPSet struct {
	root *node
	free *node
	pool []node
}

const (
	START_BYTE = byte(0x80)
)

var (
	ErrNodeBusy = errors.New("node is busy")
	ErrNotFound = errors.New("no such node")
	ErrBadIP    = errors.New("bad IP address or mask")
	MASK_32     = net.CIDRMask(8*net.IPv4len, 8*net.IPv4len)
	MASK_128    = net.CIDRMask(8*net.IPv6len, 8*net.IPv6len)
	ALLOC_LEN   = 4096 / unsafe.Sizeof(node{})
)

func NewSet() *IPSet {
	set := &IPSet{}
	set.root = set.newNode()
	return set
}

func (s *IPSet) insert(key net.IP, mask net.IPMask, value interface{}, overwrite bool) error {
	if len(key) != len(mask) {
		return ErrBadIP
	}

	i := 0
	bitmap := START_BYTE
	node := s.root
	next := s.root

	for bitmap&mask[i] != 0 {
		if key[i]&bitmap != 0 {
			next = node.right
		} else {
			next = node.left
		}
		if next == nil {
			break
		}

		node = next

		if bitmap >>= 1; bitmap == 0 {
			if i++; i == len(key) {
				break
			}
			bitmap = START_BYTE
		}

	}

	if next != nil {
		if node.value != nil && !overwrite {
			return ErrNodeBusy
		}
		node.value = value
		return nil
	}

	for bitmap&mask[i] != 0 {
		next = s.newNode()
		next.parent = node
		if key[i]&bitmap != 0 {
			node.right = next
		} else {
			node.left = next
		}
		node = next
		if bitmap >>= 1; bitmap == 0 {
			if i++; i == len(key) {
				break
			}
			bitmap = START_BYTE
		}
	}
	node.value = value

	return nil
}

func (s *IPSet) delete(key net.IP, mask net.IPMask, sub bool) error {
	if len(key) != len(mask) {
		return ErrBadIP
	}

	i := 0
	bitmap := START_BYTE
	node := s.root

	for node != nil && bitmap&mask[i] != 0 {
		if key[i]&bitmap != 0 {
			node = node.right
		} else {
			node = node.left
		}
		if bitmap >>= 1; bitmap == 0 {
			if i++; i == len(key) {
				break
			}
			bitmap = START_BYTE
		}
	}

	if node == nil {
		return ErrNotFound
	}

	if !sub && (node.right != nil || node.left != nil) {
		// trim value
		if node.value != nil {
			node.value = nil
			return nil
		}
		return ErrNotFound
	}

	// trim leaf
	for {
		if node.parent.right == node {
			node.parent.right = nil
		} else {
			node.parent.left = nil
		}
		// free
		node.right = s.free
		s.free = node

		// move to parent
		node = node.parent
		if node.right != nil || node.left != nil || node.value != nil {
			break
		}
		if node.parent == nil {
			break
		}
	}

	return nil
}

func (s *IPSet) find(key net.IP, mask net.IPMask) (value interface{}, err error) {
	if len(key) != len(mask) {
		return nil, ErrBadIP
	}

	i := 0
	bitmap := START_BYTE
	node := s.root

	for node != nil {
		if node.value != nil {
			value = node.value
		}
		if key[i]&bitmap != 0 {
			node = node.right
		} else {
			node = node.left
		}
		if mask[i]&bitmap == 0 {
			break
		}
		if bitmap >>= 1; bitmap == 0 {
			i, bitmap = i+1, START_BYTE
			if i >= len(key) {
				if node != nil {
					value = node.value
				}
				break
			}
		}
	}
	return value, nil
}

func (s *IPSet) newNode() (p *node) {
	if s.free != nil {
		p = s.free
		s.free = s.free.right
		p.right = nil
		p.parent = nil
		p.left = nil
		p.value = nil
		return p
	}

	size := len(s.pool)
	if size == cap(s.pool) {
		s.pool = make([]node, ALLOC_LEN)[:1]
		size = 0
	} else {
		s.pool = s.pool[:size+1]
	}
	return &(s.pool[size])
}

func (s *IPSet) Add(cidr *net.IPNet, val interface{}) error {
	return s.insert(cidr.IP, cidr.Mask, val, false)
}

func (s *IPSet) Set(cidr *net.IPNet, val interface{}) error {
	return s.insert(cidr.IP, cidr.Mask, val, true)
}

func (s *IPSet) Sub(cidr *net.IPNet) error {
	return s.delete(cidr.IP, cidr.Mask, true)
}

func (s *IPSet) Remove(cidr *net.IPNet) error {
	return s.delete(cidr.IP, cidr.Mask, false)
}

func (s *IPSet) Get(cidr *net.IPNet) (interface{}, error) {
	return s.find(cidr.IP, cidr.Mask)
}

func (s *IPSet) GetByIP(ip net.IP) (interface{}, error) {
	if len(ip) == net.IPv4len {
		return s.find(ip, MASK_32)
	}
	return s.find(ip, MASK_128)
}
