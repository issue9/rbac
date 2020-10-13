// SPDX-License-Identifier: MIT

package rbac

import (
	"testing"

	"github.com/issue9/assert"
)

func TestRBAC_NewRole(t *testing.T) {
	a := assert.New(t)

	inst, mem := newRBAC(a)
	id, err := inst.NewRole(0, 0)
	a.NotError(err).
		True(id > 0).
		Equal(1, len(mem.roles)).
		Equal(1, len(inst.roles)).
		Equal(inst, inst.roles[id].rbac).
		Equal(id, inst.maxRoleID)

	id2, err := inst.NewRole(1, id, id)
	a.NotError(err).
		True(id2 > 0).
		Equal(2, len(mem.roles)).
		Equal(id2, inst.maxRoleID)

	// exclude 不存在
	id3, err := inst.NewRole(1, id, id, 10001)
	a.Error(err).
		Empty(id3).
		Equal(2, len(mem.roles)).
		Equal(id2, inst.maxRoleID)

	// parent 不存在
	id3, err = inst.NewRole(1, 10001)
	a.Error(err).
		Empty(id3).
		Equal(2, len(mem.roles)).
		Equal(id2, inst.maxRoleID)
}

func TestRBAC_DelRole(t *testing.T) {
	a := assert.New(t)

	// 删除不存在的角色
	inst, mem := newRBAC(a)
	a.NotError(inst.DelRole(1))

	id, err := inst.NewRole(0, 0)
	a.NotError(err).True(id > 0)
	a.NotError(inst.DelRole(id))
	a.Equal(0, len(mem.roles))

	// 删除有子类的角色
	id, err = inst.NewRole(0, 0)
	id2, err := inst.NewRole(0, id)
	a.NotError(err).True(id2 > 0)
	a.ErrorString(inst.DelRole(id), "父类")
	a.Equal(2, len(mem.roles))

	inst.users["uid-1"] = []int{id2, id}
	a.NotError(inst.DelRole(id2))
	a.Equal(1, len(mem.roles))
	a.Equal(inst.users["uid-1"], []int{id})
}

func TestRBAC_SetCount(t *testing.T) {
	a := assert.New(t)

	inst, _ := newRBAC(a)
	a.ErrorString(inst.SetCount(1, -1), "参数")
	a.ErrorString(inst.SetCount(1, 1), "不存在")

	id, err := inst.NewRole(0, 0)
	a.NotError(err).True(id > 0)
	inst.users["uid-1"] = []int{id}
	inst.users["uid-2"] = []int{id}
	inst.users["uid-3"] = []int{id}

	a.ErrorIs(inst.SetCount(id, 2), ErrTooManyUsers) // 原本有 3 个用户关联，无法改为 2

	a.NotError(inst.SetCount(id, 3))
	a.NotError(inst.SetCount(id, 3))  // 数值未变
	a.NotError(inst.SetCount(id, 10)) // 数值变大
	a.NotError(inst.SetCount(id, 5))  // 数值变小
}

func TestRBAC_SetExclude(t *testing.T) {
	a := assert.New(t)

	inst, _ := newRBAC(a)

	id, err := inst.NewRole(0, 0)
	a.NotError(err).True(id > 0).
		Empty(inst.roles[id].excludes)

	// 未指定 excludes
	a.NotError(inst.SetExclude(id))
	a.Empty(inst.roles[id].excludes)

	// 角色不存在
	a.ErrorString(inst.SetExclude(100, id), "100 不存在")

	// 指定的 excludes 不存在
	a.ErrorString(inst.SetExclude(id, 101), "101 不存在")

	id2, err := inst.NewRole(0, id)
	a.NotError(err).True(id2 > 0)
	id3, err := inst.NewRole(0, id)
	a.NotError(err).True(id3 > 0)
	inst.users["user-1"] = []int{id, id3}

	// 指定的 excludes 与当前角色的用户关联
	a.ErrorString(inst.SetExclude(id3, id), "同时关联")

	// 指定的 excludes 与当前角色的用户关联
	a.NotError(inst.SetExclude(id2, id))
}

func TestRBAC_Allow_Deny(t *testing.T) {
	a := assert.New(t)

	inst, _ := newRBAC(a)

	id, err := inst.NewRole(0, 0)
	a.NotError(err).True(id > 0)

	// Allow 未指定资源
	a.NotError(inst.Allow(id))
	a.Empty(inst.roles[id].resources)

	// Allow 不存在的角色
	a.NotError(inst.Allow(0))
	a.Empty(inst.roles[id].resources)

	// Allow 正常指定资源
	a.NotError(inst.Allow(id, "res-1", "res-2"))
	a.Equal(inst.roles[id].resources, []string{"res-1", "res-2"})

	// Allow 添加资源
	a.NotError(inst.Allow(id, "res-1", "res-4"))
	a.Equal(inst.roles[id].resources, []string{"res-1", "res-2", "res-4"})

	// Deny 未指定资源
	a.NotError(inst.Allow(id))
	a.Equal(inst.roles[id].resources, []string{"res-1", "res-2", "res-4"})

	// Deny 不存在的角色
	a.NotError(inst.Deny(0))
	a.Equal(inst.roles[id].resources, []string{"res-1", "res-2", "res-4"})

	// Deny 正常删除
	a.NotError(inst.Deny(id, "res-1", "res-4"))
	a.Equal(inst.roles[id].resources, []string{"res-2"})

	// 子角色的相关操作

	id2, err := inst.NewRole(0, id)
	a.NotError(err).True(id2 > 0)
	id3, err := inst.NewRole(0, id2)
	a.NotError(err).True(id2 > 0)

	// allow 非父角色的资源
	a.ErrorString(inst.Allow(id2, "res-1", "res-2"), "继承父角色")

	// allow
	a.NotError(inst.Allow(id2, "res-2"))
	a.Equal(inst.roles[id2].resources, []string{"res-2"})
	a.NotError(inst.Allow(id3, "res-2"))
	a.Equal(inst.roles[id3].resources, []string{"res-2"})

	// Deny 子角色 id2 还依赖该资源
	a.ErrorString(inst.Deny(id, "res-2"), "也允许访问")
	a.Equal(inst.roles[id2].resources, []string{"res-2"})
	a.Equal(inst.roles[id].resources, []string{"res-2"})

	// Deny 正常
	a.NotError(inst.Deny(id3, "res-2"))
	a.NotError(inst.Deny(id2, "res-2"))
	a.NotError(inst.Deny(id, "res-2"))
	a.Empty(inst.roles[id3].resources)
	a.Empty(inst.roles[id2].resources)
	a.Empty(inst.roles[id].resources)
}
