#include "test-iter-classes.h"

#include <CUnit/CUnit.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <sepol/policydb.h>
#include <sepol/class_record.h>
#include <sepol/classes.h>

#include "helpers.h"

extern sepol_handle_t *handle;
extern sepol_policydb_t *empty_policy;
extern sepol_policydb_t *iter_policy;


struct expected_class {
	int seen;

	const char *name;
	const char *common;
	uint32_t nperms;
	const char *perms[32];
	uint32_t nconstraints;
	struct {
		int seen;

		uint32_t nperms;
		const char *perms[32];
		uint32_t nexprs;
		struct {
			uint32_t type;
			uint32_t attr;
			uint32_t op;
			uint32_t nnames;
			const char *names[32];
		} exprs[32];
	} constraints[32];
	char default_user;
	char default_role;
	char default_type;
	char default_range;
};

struct expected_class expected_classes[] = {
	{ 
		0, "CLASS1", "COMMON1",
		1, { "PERM1" },
		2,
		{
			{ 0, 1, { "PERM1" }, 1, { { SEPOL_CEXPR_TYPE_NAMES, SEPOL_CEXPR_ATTR_TYPE, SEPOL_CEXPR_OP_EQ, 1, { "TYPE1" } } } },
			{ 0, 1, { "PERM1" }, 1, { { SEPOL_CEXPR_TYPE_NAMES, SEPOL_CEXPR_ATTR_TYPE, SEPOL_CEXPR_OP_EQ, 1, { "TYPE1" } } } },
		},
		0, 0, 0, 0
	},
	{ 0, "CLASS01", NULL, 1, { "PERM01" }, 0, { { 0, 0, { NULL }, 0, { { 0, 0, 0, 0, { NULL } } } } }, 0, 0, 0, 0 },
	{ 0, "CLASS02", NULL, 1, { "PERM02" }, 0, { { 0, 0, { NULL }, 0, { { 0, 0, 0, 0, { NULL } } } } }, 0, 0, 0, 0 },
	{ 0, "CLASS03", NULL, 1, { "PERM03" }, 0, { { 0, 0, { NULL }, 0, { { 0, 0, 0, 0, { NULL } } } } }, 0, 0, 0, 0 },
	{ 0, "CLASS04", NULL, 1, { "PERM04" }, 0, { { 0, 0, { NULL }, 0, { { 0, 0, 0, 0, { NULL } } } } }, 0, 0, 0, 0 },
	{ 0, "CLASS05", NULL, 1, { "PERM05" }, 0, { { 0, 0, { NULL }, 0, { { 0, 0, 0, 0, { NULL } } } } }, 0, 0, 0, 0 },
	{ 0, "CLASS06", NULL, 1, { "PERM06" }, 0, { { 0, 0, { NULL }, 0, { { 0, 0, 0, 0, { NULL } } } } }, 0, 0, 0, 0 },
	{ 0, NULL,      NULL, 0, { NULL },     0, { { 0, 0, { NULL }, 0, { { 0, 0, 0, 0, { NULL } } } } }, 0, 0, 0, 0 },
};

static void unseen(void)
{
	for (struct expected_class *e = expected_classes; !e->name; e++) {
		e->seen = 0;
	}
}

static void seen_constraint(const sepol_constraint_t *item, struct expected_class *e)
{
	
}

static void seen(const sepol_class_t *item)
{
	const char *actual_name = sepol_class_get_name(item);
	const char *actual_common = sepol_class_get_common(item);
	uint32_t nactual_perms;
	const char **actual_perms;
	CU_ASSERT_EQUAL_FATAL(sepol_class_get_perms(handle, item, &actual_perms, &nactual_perms), 0);
	uint32_t nactual_constraints;
	const sepol_constraint_t **actual_constraints;
	CU_ASSERT_EQUAL_FATAL(sepol_class_get_constraints(handle, item, &actual_constraints, &nactual_constraints), 0);
	char actual_default_user = sepol_class_get_default_user(item);
	char actual_default_role = sepol_class_get_default_role(item);
	char actual_default_type = sepol_class_get_default_type(item);
	char actual_default_range = sepol_class_get_default_range(item);
	
	struct expected_class *e;
	for (e = expected_classes; e->name; e++) {
		if (strcmp(actual_name, e->name) == 0)
			break;
	}
	CU_ASSERT_PTR_NOT_NULL_FATAL(e->name);
	e->seen = 1;
	
	if (e->common) {
		CU_ASSERT_STRING_EQUAL(actual_common, e->common);
	} else {
		CU_ASSERT_PTR_NULL(actual_common);
	}

	CU_ASSERT_EQUAL(nactual_perms, e->nperms);
	qsort(actual_perms, nactual_perms, sizeof(char *), qstrcmp);
	for (size_t i = 0; i < nactual_perms && i < e->nperms; i++) {
		CU_ASSERT_STRING_EQUAL(actual_perms[i], e->perms[i]);
	}

	CU_ASSERT_EQUAL(actual_default_user, e->default_user);
	CU_ASSERT_EQUAL(actual_default_role, e->default_role);
	CU_ASSERT_EQUAL(actual_default_type, e->default_type);
	CU_ASSERT_EQUAL(actual_default_range, e->default_range);
	
	free(actual_perms);
}

void test_iter_classes_non_empty(void)
{
	unseen();
	sepol_class_t *item;
	sepol_class_iter_t *class_iter;
	CU_ASSERT_EQUAL_FATAL(sepol_class_iter_create(handle, iter_policy, &class_iter), 0);

	while (1) {
		CU_ASSERT_EQUAL(sepol_class_iter_next(handle, class_iter, &item), 0);
		if (!item)
			break;
		seen(item);
		sepol_class_free(item);
	}
	CU_ASSERT_EQUAL(sepol_class_iter_next(handle, class_iter, &item), 0);
	CU_ASSERT_PTR_NULL(item);

	for (struct expected_class *e = expected_classes; e->name; e++) {
		CU_ASSERT_TRUE(e->seen);
	}

	sepol_class_iter_destroy(class_iter);
}
