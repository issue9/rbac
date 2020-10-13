// SPDX-License-Identifier: MIT

package rbac

import (
	"testing"

	"github.com/issue9/assert"
)

func newRBAC(a *assert.Assertion) (*RBAC, *memory) {
	mem := newMemory()
	a.NotNil(mem)

	inst, err := New(mem)
	a.NotError(err).NotNil(inst)

	return inst, mem
}

func TestNew(t *testing.T) {
	a := assert.New(t)

	s := newMemory()
	inst, err := New(s)
	a.NotError(err).NotNil(inst).Equal(inst.maxRoleID, 0)

	s.roles[100] = &memoryRole{ID: 100}
	s.roles[10] = &memoryRole{ID: 10, Resources: []string{"res1", "res2"}}
	inst, err = New(s)
	a.NotError(err).NotNil(inst)
	a.Equal(inst.maxRoleID, 100).
		Equal(inst.Role(10).ID, 10).
		Equal(inst.Role(10).Resources, []string{"res1", "res2"})
}

func TestRBAC_Related_Unrelated_IsAllow(t *testing.T) {
	a := assert.New(t)

	inst, _ := newRBAC(a)
	id, err := inst.NewRole(0, 0)
	a.NotError(err).True(id > 0)
	id2, err := inst.NewRole(0, id)
	a.NotError(err).True(id2 > 0)

	a.NotError(inst.Allow(id, "res-1"))

	// Related 未指定角色
	a.NotError(inst.Related("uid-1"))
	a.Empty(inst.users["uid-1"])

	// Related 不存在的角色
	a.ErrorString(inst.Related("uid-1", id, id2, 10001), "并不存在")
	a.Empty(inst.users["uid-1"])

	// Related
	a.NotError(inst.Related("uid-1", id, id2))
	a.Equal(inst.users["uid-1"], []int{id, id2})
	a.NotError(inst.Related("uid-1", id, id2))
	a.Equal(inst.users["uid-1"], []int{id, id2})

	// IsAllow
	allowed, err := inst.IsAllow("uid-1", "not-exists")
	a.NotError(err).False(allowed)
	allowed, err = inst.IsAllow("uid-1", "res-1")
	a.NotError(err).True(allowed)

	// Unrelated 未指定角色
	a.NotError(inst.Unrelated("uid-1"))
	a.Equal(inst.users["uid-1"], []int{id, id2})

	// Unrelated 不存在的角色
	a.ErrorString(inst.Unrelated("uid-1", id, id2, 10001), "并不存在")
	a.Equal(inst.users["uid-1"], []int{id, id2})

	// Unrelated
	a.NotError(inst.Unrelated("uid-1", id, id2))
	a.Empty(inst.users["uid-1"])
	a.NotError(inst.Unrelated("uid-1", id, id2))

	allowed, err = inst.IsAllow("uid-1", "res-1")
	a.NotError(err).False(allowed)
}
