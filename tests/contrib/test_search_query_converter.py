"""
Tests for ABAC Condition Converter.
"""

from unittest.mock import Mock

from cqrs_ddd_auth.contrib.search_query_dsl.converter import (
    ABACConditionConverter,
    FieldMapping,
)


def test_convert_single_condition():
    converter = ABACConditionConverter()
    dsl = {"op": "=", "attr": "status", "val": "active"}

    query = converter.convert(dsl)

    assert query.groups
    group = query.groups[0]
    assert len(group.conditions) == 1

    cond = group.conditions[0]
    assert cond.field == "status"
    assert cond.operator == "="
    assert cond.value == "active"


def test_convert_recursive_group():
    converter = ABACConditionConverter()
    dsl = {
        "op": "and",
        "conditions": [
            {"op": "=", "attr": "status", "val": "active"},
            {"op": "in", "attr": "type", "val": [1, 2]},
        ],
    }

    query = converter.convert(dsl)
    group = query.groups[0]

    assert group.group_operator == "and"
    assert len(group.conditions) == 2

    c1 = group.conditions[0]
    assert c1.operator == "="

    c2 = group.conditions[1]
    assert c2.operator == "in"
    assert c2.value == [1, 2]


def test_field_mapping():
    mapping = FieldMapping(mappings={"owner": "created_by"}, external_id_field="uuid")
    converter = ABACConditionConverter(field_mapping=mapping)

    dsl = {
        "op": "or",
        "conditions": [
            {"op": "=", "attr": "owner", "val": "u1"},
            {"op": "in", "attr": "external_id", "val": ["id1", "id2"]},
        ],
    }

    query = converter.convert(dsl)
    group = query.groups[0]

    # Check "owner" -> "created_by"
    assert group.conditions[0].field == "created_by"

    # Check "external_id" -> "uuid"
    assert group.conditions[1].field == "uuid"


def test_convert_spatial():
    converter = ABACConditionConverter()
    dsl = {"op": "st_dwithin", "attr": "location", "val": "POINT(0 0)", "args": 1000}

    query = converter.convert(dsl)
    cond = query.groups[0].conditions[0]

    assert cond.field == "location"
    assert cond.operator == "dwithin"
    assert cond.value_type == "geometry"
    assert cond.value == {"geometry": "POINT(0 0)", "distance": 1000}


def test_convert_result_granted():
    converter = ABACConditionConverter()
    result = Mock()
    result.granted_all = True
    result.denied_all = False

    auth_filter = converter.convert_result(result)
    assert auth_filter.granted_all is True


def test_convert_result_denied():
    converter = ABACConditionConverter()
    result = Mock()
    result.granted_all = False
    result.denied_all = True

    auth_filter = converter.convert_result(result)
    assert auth_filter.denied_all is True


def test_convert_result_conditions():
    converter = ABACConditionConverter()
    result = Mock()
    result.granted_all = False
    result.denied_all = False
    result.conditions_dsl = {"op": "=", "attr": "a", "val": 1}
    result.has_context_refs = True

    auth_filter = converter.convert_result(result)
    assert auth_filter.search_query is not None
    assert auth_filter.has_context_refs is True
