// SPDX-License-Identifier: MIT

package rbac

import "github.com/issue9/sliceutil"

var _ Store = &memory{}

// 用于测试的 Store 实现
type memory struct {
	roles map[int]*memoryRole
}

type memoryRole struct {
	ID        int
	Count     int
	Parent    int
	Excludes  []int
	Resources []string
	users     []string
}

func newMemory() *memory {
	return &memory{
		roles: make(map[int]*memoryRole, 10),
	}
}

func (mem *memory) LoadRoles() ([]*Role, error) {
	roles := make([]*Role, 0, len(mem.roles))

	for _, r := range mem.roles {
		roles = append(roles, &Role{
			ID:        r.ID,
			Count:     r.Count,
			Parent:    r.Parent,
			Excludes:  r.Excludes,
			Resources: r.Resources,
		})
	}

	return roles, nil
}

func (mem *memory) DelRole(id int) error {
	delete(mem.roles, id)
	return nil
}

func (mem *memory) AddRole(id, count, parent int, exclude ...int) error {
	mem.roles[id] = &memoryRole{
		ID:       id,
		Count:    count,
		Parent:   parent,
		Excludes: exclude,
	}

	return nil
}

func (mem *memory) SetCount(id, count int) error {
	mem.roles[id].Count = count
	return nil
}

func (mem *memory) SetExclude(id int, exclude ...int) error {
	mem.roles[id].Excludes = exclude
	return nil
}

func (mem *memory) AddResource(role int, res ...string) error {
	r := mem.roles[role]

	for _, resID := range res {
		if sliceutil.Count(r.Resources, func(i int) bool { return r.Resources[i] == resID }) > 0 {
			continue
		}
		r.Resources = append(r.Resources, resID)
	}

	return nil
}

func (mem *memory) DelResource(role int, res ...string) error {
	r := mem.roles[role]

	for _, resID := range res {
		if size := sliceutil.QuickDelete(r.Resources, func(i int) bool { return r.Resources[i] == resID }); size >= 0 {
			r.Resources = r.Resources[:size]
		}
	}

	return nil
}

func (mem *memory) Relate(uid string, role ...int) error {
	for _, rid := range role {
		r := mem.roles[rid]
		if sliceutil.Count(r.users, func(i int) bool { return r.users[i] == uid }) >= 0 {
			continue
		}
		r.users = append(r.users, uid)
	}

	return nil
}

func (mem *memory) Unrelate(uid string, role ...int) error {
	for _, rid := range role {
		r := mem.roles[rid]
		if size := sliceutil.QuickDelete(r.users, func(i int) bool { return r.users[i] == uid }); size >= 0 {
			r.users = r.users[:size]
		}
	}

	return nil
}

func (mem *memory) LoadRelate(uid string) ([]int, error) {
	roles := make([]int, 0, 10)
	for _, role := range mem.roles {
		if sliceutil.Count(role.users, func(i int) bool { return role.users[i] == uid }) >= 0 {
			roles = append(roles, role.ID)
			continue
		}
	}

	return roles, nil
}
