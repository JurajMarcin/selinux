#include <sepol/type_record.h>

#include <stdlib.h>
#include <string.h>

#include "debug.h"

struct sepol_type {
	/* This type's name */
	char *name;

	/* This type's flavor */
	uint32_t flavor;
	/* This type attribute's subtypes */
	uint32_t num_types;
	char **types;
	/* This type's flags */
	uint32_t flags;

	/* This type's bounds type, if exists */
	char *bounds;

	/* This alias' primary type name */
	char *alias_of;
};

struct sepol_type_key {
	/* This type's name */
	char *name;
};

int sepol_type_key_create(sepol_handle_t *handle,
			  const char *name, sepol_type_key_t **key_ptr)
{
	sepol_type_key_t *tmp_key = malloc(sizeof(sepol_type_key_t));

	if (!tmp_key) {
		ERR(handle, "out of memory, could not create selinux type key");
		return STATUS_ERR;
	}

	tmp_key->name = strdup(name);
	if (!tmp_key->name) {
		ERR(handle, "out of memory, could not create selinux type key");
		free(tmp_key);
		return STATUS_ERR;
	}

	*key_ptr = tmp_key;
	return STATUS_SUCCESS;
}

void sepol_type_key_unpack(const sepol_type_key_t *key, const char **name)
{
	*name = key->name;
}

int sepol_type_key_extract(sepol_handle_t *handle, const sepol_type_t *type,
			   sepol_type_key_t **key_ptr)
{
	if (sepol_type_key_create(handle, type->name, key_ptr) < 0) {
		ERR(handle, "could not extract key from type %s", type->name);
		return STATUS_ERR;
	}
	return STATUS_SUCCESS;
}

void sepol_type_key_free(sepol_type_key_t *key)
{
	if (!key)
		return;
	free(key->name);
	free(key);
}

int sepol_type_compare(const sepol_type_t *type, const sepol_type_key_t *key)
{
	return strcmp(type->name, key->name);
}

int sepol_type_compare2(const sepol_type_t *type, const sepol_type_t *type2)
{
	return strcmp(type->name, type2->name);
}

/* Name */
const char *sepol_type_get_name(const sepol_type_t * type)
{

	return type->name;
}

int sepol_type_set_name(sepol_handle_t * handle, sepol_type_t * type,
			const char *name)
{
	char *tmp_name = strdup(name);
	if (!tmp_name) {
		ERR(handle, "out of memory, could not set name");
		return STATUS_ERR;
	}
	free(type->name);
	type->name = tmp_name;
	return STATUS_SUCCESS;
}

/* Flavor */
uint32_t sepol_type_get_flavor(const sepol_type_t *type)
{
	return type->flavor;
}

int sepol_type_set_flavor(sepol_type_t *type, uint32_t flavor)
{
	type->flavor = flavor;
	return STATUS_SUCCESS;
}

/* Subtypes/Attributes */
int sepol_type_has_subtype(const sepol_type_t *type, const char *subtype)
{
	for (uint32_t i = 0; i < type->num_types; i++) {
		if (!strcmp(type->types[i], subtype))
			return 1;
	}
	return 0;
}

int sepol_type_get_subtypes(sepol_handle_t *handle, const sepol_type_t *type,
			    const char ***subtypes,
			    uint32_t *num_subtypes)
{
	const char **tmp = malloc(sizeof(char *) * type->num_types);
	if (tmp == NULL) {
		ERR(handle,
      		    "out of memory, cannot get subtypes of selinux type");
		return STATUS_ERR;
	}

	for (uint32_t i = 0; i < type->num_types; i++) {
		tmp[i] = type->types[i];
	}

	*subtypes = tmp;
	*num_subtypes = type->num_types;
	return STATUS_SUCCESS;
}

int sepol_type_add_subtype(sepol_handle_t *handle, sepol_type_t *type,
			   const char *subtype)
{
	if (sepol_type_has_subtype(type, subtype))
		return STATUS_SUCCESS;

	char **tmp = reallocarray(type->types, type->num_types + 1,
			   	  sizeof(char *));
	if (!tmp) {
		ERR(handle,
      		    "out of memory, cannot add subtype to selinux type");
		return STATUS_ERR;
	}
	type->types = tmp;

	type->types[type->num_types] = strdup(subtype);
	if (!type->types[type->num_types]) {
		ERR(handle,
      		    "out of memory, cannot add subtype to selinux type");
		return STATUS_ERR;
	}
	type->num_types++;

	return STATUS_SUCCESS;
}

int sepol_type_del_subtype(sepol_handle_t *handle __attribute__ ((unused)),
			   sepol_type_t *type, const char *subtype)
{
	for (uint32_t i = 0; i < type->num_types; i++) {
		if (!strcmp(type->types[i], subtype)) {
			free(type->types[i]);
			type->types[i] = type->types[type->num_types - 1];
			type->num_types--;
		}
	}
	return STATUS_SUCCESS;
}

/* Flags */
int sepol_type_has_flag(const sepol_type_t *type, uint32_t flag)
{
	return (type->flags & flag) != 0;
}

int sepol_type_set_flag(sepol_type_t *type, uint32_t flag)
{
	type->flags |= flag;
	return STATUS_SUCCESS;
}

int sepol_type_unset_flag(sepol_type_t *type, uint32_t flag)
{
	type->flags &= ~flag;
	return STATUS_SUCCESS;
}

/* Aliases */
const char *sepol_type_get_alias_of(const sepol_type_t *type)
{
	return type->alias_of;
}

int sepol_type_set_alias_of(sepol_handle_t *handle, sepol_type_t *type,
				   const char *name)
{
	type->alias_of = strdup(name);
	if (!type->alias_of) {
		ERR(handle,
		    "out of memory, cannot set selinux alias primary type name");
		return STATUS_ERR;
	}
	return STATUS_SUCCESS;
}

/* Bounds */
const char *sepol_type_get_bounds(const sepol_type_t *type)
{
	return type->bounds;
}

int sepol_type_set_bounds(sepol_handle_t *handle, sepol_type_t *type,
			  const char *bounds)
{
	type->bounds = strdup(bounds);
	if (!type->bounds) {
		ERR(handle,
		    "out of memory, cannot set selinux type bounds name");
		return STATUS_ERR;
	}
	return STATUS_SUCCESS;
}

/* Create/Clone/Destroy */
int sepol_type_create(sepol_handle_t *handle, sepol_type_t **type_ptr)
{
	*type_ptr = malloc(sizeof(sepol_type_t));
	if (!type_ptr) {
		ERR(handle, "out of memory, could not create type record");
		return STATUS_ERR;
	}

	memset(*type_ptr, 0, sizeof(sepol_type_t));

	return STATUS_SUCCESS;
}

int sepol_type_clone(sepol_handle_t *handle, const sepol_type_t *type,
		     sepol_type_t **type_ptr)
{
	sepol_type_t *tmp;
	if (sepol_type_create(handle, &tmp))
		return STATUS_ERR;

	tmp->name = strdup(type->name);
	if (!tmp->name) {
		ERR(handle, "out of memory, could not set name");
		return STATUS_ERR;
	}
	tmp->flags = type->flags;

	*type_ptr = tmp;
	return STATUS_SUCCESS;
}

void sepol_type_free(sepol_type_t *type)
{
	if (!type)
		return;

	free(type->name);
	for (size_t i = 0; i < type->num_types; i++)
		free(type->types[i]);
	free(type->types);
	free(type->bounds);
	free(type->alias_of);
	free(type);
}
