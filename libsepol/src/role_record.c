#include <sepol/role_record.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sepol/policydb/util.h"
#include "debug.h"

struct sepol_role {
	char *name; // role name
	char **types; // authorized types
	uint32_t num_types;
	char *bounds; // bounded role
	uint32_t flavor; // role or attribute
	char **subroles; // roles within attribute
	uint32_t num_subroles;
};

struct sepol_role_key {
	const char *name;
};

/* Key */
int sepol_role_key_create(sepol_handle_t *handle, const char *name,
			  sepol_role_key_t **key)
{
	sepol_role_key_t *tmp_key = malloc(sizeof(sepol_role_key_t));
	if (!tmp_key)
		goto omem;
	tmp_key->name = strdup(name);
	if (!tmp_key->name)
		goto omem;
	
	*key = tmp_key;
	return STATUS_SUCCESS;

omem:
	ERR(handle, "out of memory");
	free(tmp_key);
	return STATUS_ERR;
}

void sepol_role_key_unpack(const sepol_role_key_t *key, const char **name)
{
	*name = key->name;
}

int sepol_role_key_extract(sepol_handle_t *handle, const sepol_role_t *role,
			   sepol_role_key_t **key)
{
	return sepol_role_key_create(handle, role->name, key);
}

void sepol_role_key_free(sepol_role_key_t *key)
{
	free(key);
}

int sepol_role_compare(const sepol_role_t *role, const sepol_role_key_t *key)
{
	return strcmp(role->name, key->name);
}

int sepol_role_compare2(const sepol_role_t *role, const sepol_role_t *role2)
{
	return strcmp(role->name, role2->name);
}

/* Role name */
const char *sepol_role_get_name(const sepol_role_t *role)
{
	return role->name;
}

int sepol_role_set_name(sepol_handle_t *handle, sepol_role_t *role,
			const char *name)
{
	char *tmp_name = strdup(name);
	if (!tmp_name) {
		ERR(handle, "out of memory, could not set name");
		return STATUS_ERR;
	}
	free(role->name);
	role->name = tmp_name;
	return STATUS_SUCCESS;
}

/* Authorized types */
int sepol_role_has_type(const sepol_role_t *role, const char *type)
{
	return string_list_contains(role->types, role->num_types, type);
}

int sepol_role_get_types(sepol_handle_t *handle, const sepol_role_t *role,
			 const char ***types, uint32_t *num_types)
{
	return string_list_scopy(handle, role->types, role->num_types, types,
				 num_types);
}

int sepol_role_add_type(sepol_handle_t *handle, sepol_role_t *role,
			const char *type)
{
	return string_list_add(handle, &role->types, &role->num_types, type);
}

int sepol_role_del_type(sepol_handle_t *handle __attribute__ ((unused)),
			sepol_role_t *role, const char *type)
{
	return string_list_del(role->types, &role->num_types, type);
}

/* Bounds role */
const char *sepol_role_get_bounds(const sepol_role_t *role)
{
	return role->bounds;
}

int sepol_role_set_bounds(sepol_handle_t *handle, sepol_role_t *role,
			  const char *bounds)
{
	char *tmp_bounds = strdup(bounds);
	if (!tmp_bounds) {
		ERR(handle, "out of memory");
		return STATUS_ERR;
	}

	role->bounds = tmp_bounds;

	return STATUS_SUCCESS;
}

/* Flavor */
uint32_t sepol_role_get_flavor(const sepol_role_t *role)
{
	return role->flavor;
}

int sepol_role_set_flavor(sepol_role_t *role, uint32_t flavor)
{
	role->flavor = flavor;
	return STATUS_SUCCESS;
}

/* Subroles in attribute */
int sepol_role_get_subroles(sepol_handle_t *handle, const sepol_role_t *role,
			    const char ***subroles, uint32_t *num_subroles)
{
	return string_list_scopy(handle, role->subroles, role->num_subroles,
				 subroles, num_subroles);
}

int sepol_role_add_subrole(sepol_handle_t *handle, sepol_role_t *role,
			   const char *subrole)
{
	return string_list_add(handle, &role->subroles, &role->num_subroles,
			       subrole);
}

int sepol_role_del_subrole(sepol_handle_t *handle __attribute__ ((unused)),
			   sepol_role_t *role, const char *subrole)
{
	return string_list_del(role->subroles, &role->num_subroles, subrole);
}

/* Create/Clone/Destroy */
int sepol_role_create(sepol_handle_t *handle, sepol_role_t **role_ptr)
{
	sepol_role_t *tmp = malloc(sizeof(sepol_role_t));
	if (!tmp) {
		ERR(handle, "out of memory");
		return STATUS_ERR;
	}
	memset(tmp, 0, sizeof(sepol_role_t));
	*role_ptr = tmp;
	return STATUS_SUCCESS;
}

int sepol_role_clone(sepol_handle_t *handle, const sepol_role_t *role,
		     sepol_role_t **role_ptr)
{
	sepol_role_t *tmp = NULL;
	if (sepol_role_create(handle, &tmp))
		goto err;

	if (sepol_role_set_name(handle, tmp, role->name))
		goto err;
	for (size_t i = 0; i < role->num_types; i++) {
		if (sepol_role_add_type(handle, tmp, role->types[i]))
			goto err;
	}
	if (sepol_role_set_bounds(handle, tmp, role->bounds))
		goto err;

	tmp->flavor = role->flavor;

	*role_ptr = tmp;
	return STATUS_SUCCESS;

err:
	sepol_role_free(tmp);
	return STATUS_ERR;
}

void sepol_role_free(sepol_role_t *role)
{
	if (!role)
		return;

	free(role->name);
	for (size_t i = 0; i < role->num_types; i++)
		free(role->types[i]);
	free(role->types);
	free(role->bounds);
	for (size_t i = 0; i < role->num_subroles; i++)
		free(role->subroles[i]);
	free(role->subroles);
	free(role);
}
