// SPDX-License-Identifier: MIT

package rbac

// Store 数据存储接口
type Store interface {
	// 角色的操作
	LoadRoles() ([]*Role, error)
	DelRole(id int) error
	AddRole(id, count, parent int, exclude ...int) error
	SetCount(id, count int) error
	SetExclude(id int, exclude ...int) error

	// 增加角色 role 对 res 的操作权限
	//
	// 可多次调用，调用方保证给出的 res 不会有重复数据，
	// 也不会有已存在于 Store 中的数据。
	AddResource(role int, res ...string) error

	// 删除角色 role 与资源 res 的关联
	DelResource(role int, res ...string) error

	// 将用户与角色进行关联
	//
	// 可多次调用，调用方保证给出的 res 不会有重复数据，
	// 也不会有已存在于 Store 中的数据。
	Relate(uid string, role ...int) error

	// 取消用户与角角色的关联
	Unrelate(uid string, role ...int) error

	// 加载指定用户的角色列表
	LoadRelate(uid string) ([]int, error)
}
