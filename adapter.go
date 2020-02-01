/*
-------------------------------------------------
   Author :       Zhang Fan
   date：         2020-02-01
   Description :
-------------------------------------------------
*/

package zcasbin_mongo

import (
    "errors"

    "github.com/casbin/casbin/v2/model"
    "github.com/zlyuancn/zmongo"
    "go.mongodb.org/mongo-driver/bson"
)

type CasbinRule struct {
    PType string
    V0    string
    V1    string
    V2    string
    V3    string
    V4    string
    V5    string
}

type adapter struct {
    coll     *zmongo.Collection
    filtered bool
}

func NewAdapter(c *zmongo.Client, collname string) *adapter {
    return &adapter{
        coll:     c.Coll("", collname),
        filtered: false,
    }
}

func (a *adapter) dropTable() error {
    if err := a.coll.Drop(); err != nil {
        return err
    }
    return nil
}

func loadPolicyLine(line CasbinRule, model model.Model) {
    key := line.PType
    sec := key[:1]

    tokens := []string{}
    if line.V0 != "" {
        tokens = append(tokens, line.V0)
    } else {
        goto LineEnd
    }

    if line.V1 != "" {
        tokens = append(tokens, line.V1)
    } else {
        goto LineEnd
    }

    if line.V2 != "" {
        tokens = append(tokens, line.V2)
    } else {
        goto LineEnd
    }

    if line.V3 != "" {
        tokens = append(tokens, line.V3)
    } else {
        goto LineEnd
    }

    if line.V4 != "" {
        tokens = append(tokens, line.V4)
    } else {
        goto LineEnd
    }

    if line.V5 != "" {
        tokens = append(tokens, line.V5)
    } else {
        goto LineEnd
    }

LineEnd:
    model[sec][key].Policy = append(model[sec][key].Policy, tokens)
}

func (a *adapter) LoadPolicy(model model.Model) error {
    return a.LoadFilteredPolicy(model, nil)
}

func (a *adapter) LoadFilteredPolicy(model model.Model, filter interface{}) error {
    if filter == nil {
        filter = bson.M{}
        a.filtered = false
    } else {
        a.filtered = true
    }

    cur, err := a.coll.Find(filter)
    if err != nil {
        return err
    }
    defer cur.Close()

    for cur.Next() {
        line := CasbinRule{}
        if err := cur.Decode(&line); err != nil {
            return err
        }
        loadPolicyLine(line, model)
    }

    return nil
}

// 如果加载的策略已被筛选，则IsFiltered返回true
func (a *adapter) IsFiltered() bool {
    return a.filtered
}

func savePolicyLine(ptype string, rule []string) CasbinRule {
    line := CasbinRule{
        PType: ptype,
    }

    if len(rule) > 0 {
        line.V0 = rule[0]
    }
    if len(rule) > 1 {
        line.V1 = rule[1]
    }
    if len(rule) > 2 {
        line.V2 = rule[2]
    }
    if len(rule) > 3 {
        line.V3 = rule[3]
    }
    if len(rule) > 4 {
        line.V4 = rule[4]
    }
    if len(rule) > 5 {
        line.V5 = rule[5]
    }

    return line
}

func (a *adapter) SavePolicy(model model.Model) error {
    if a.filtered {
        return errors.New("无法保存筛选后的策略")
    }
    if err := a.dropTable(); err != nil {
        return err
    }

    var lines []interface{}

    for ptype, ast := range model["p"] {
        for _, rule := range ast.Policy {
            line := savePolicyLine(ptype, rule)
            lines = append(lines, &line)
        }
    }

    for ptype, ast := range model["g"] {
        for _, rule := range ast.Policy {
            line := savePolicyLine(ptype, rule)
            lines = append(lines, &line)
        }
    }

    _, err := a.coll.InsertMany(lines)
    return err
}

func (a *adapter) AddPolicy(sec string, ptype string, rule []string) error {
    line := savePolicyLine(ptype, rule)

    _, err := a.coll.InsertOne(line)
    return err
}

func (a *adapter) RemovePolicy(sec string, ptype string, rule []string) error {
    line := savePolicyLine(ptype, rule)

    if err := a.coll.MustDeleteOne(line); err != nil && err != zmongo.ErrNoDelete {
        return err
    }
    return nil
}

func (a *adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
    selector := make(map[string]interface{})
    selector["ptype"] = ptype

    if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
        if fieldValues[0-fieldIndex] != "" {
            selector["v0"] = fieldValues[0-fieldIndex]
        }
    }
    if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
        if fieldValues[1-fieldIndex] != "" {
            selector["v1"] = fieldValues[1-fieldIndex]
        }
    }
    if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
        if fieldValues[2-fieldIndex] != "" {
            selector["v2"] = fieldValues[2-fieldIndex]
        }
    }
    if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
        if fieldValues[3-fieldIndex] != "" {
            selector["v3"] = fieldValues[3-fieldIndex]
        }
    }
    if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
        if fieldValues[4-fieldIndex] != "" {
            selector["v4"] = fieldValues[4-fieldIndex]
        }
    }
    if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
        if fieldValues[5-fieldIndex] != "" {
            selector["v5"] = fieldValues[5-fieldIndex]
        }
    }

    _, err := a.coll.DeleteMany(selector)
    return err
}
