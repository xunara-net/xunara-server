package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/tailscale/hujson"
)

// ParseManaged 比历史文件入口更严格：不把拼错字段或重复键保存为“已生效”。
func ParseManaged(raw []byte) (*Document, json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > 256*1024 {
		return nil, nil, errors.New("policy document must be between 1 byte and 256 KiB")
	}
	standard, err := hujson.Standardize(raw)
	if err != nil {
		return nil, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(standard))
	if err := checkJSONKeys(decoder, 0); err != nil {
		return nil, nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, nil, errors.New("policy must contain one object")
	}
	trimmed := bytes.TrimSpace(standard)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, nil, errors.New("policy must be an object")
	}
	if err := checkManagedFieldNames(standard); err != nil {
		return nil, nil, err
	}
	var document Document
	decoder = json.NewDecoder(bytes.NewReader(standard))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, nil, err
	}
	if len(document.ACLs)+len(document.Grants) > 512 || len(document.Groups) > 256 || len(document.Hosts) > 1024 || len(document.Tests) > 256 || len(document.SSH) > 256 || len(document.NodeAttrs) > 256 {
		return nil, nil, errors.New("policy has too many rules, groups, hosts or tests")
	}
	return &document, json.RawMessage(standard), nil
}

// encoding/json 默认忽略字段大小写，托管策略必须与可视化 AST 使用同一套精确字段名。
func checkManagedFieldNames(raw []byte) error {
	if err := checkStructFieldNames(raw, reflect.TypeFor[Document]()); err != nil {
		return err
	}
	var sections map[string]json.RawMessage
	if err := json.Unmarshal(raw, &sections); err != nil {
		return err
	}
	for name, rowType := range map[string]reflect.Type{
		"acls": reflect.TypeFor[ACLRow](), "grants": reflect.TypeFor[GrantRow](),
		"ssh": reflect.TypeFor[SSHRow](), "nodeAttrs": reflect.TypeFor[NodeAttrRow](), "tests": reflect.TypeFor[Test](),
	} {
		content, exists := sections[name]
		if !exists {
			continue
		}
		var rows []json.RawMessage
		if err := json.Unmarshal(content, &rows); err != nil {
			return err
		}
		for _, row := range rows {
			if err := checkStructFieldNames(row, rowType); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	return nil
}

func checkStructFieldNames(raw []byte, rowType reflect.Type) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	known := make(map[string]bool)
	for fieldIndex := 0; fieldIndex < rowType.NumField(); fieldIndex++ {
		name := strings.Split(rowType.Field(fieldIndex).Tag.Get("json"), ",")[0]
		if name != "" && name != "-" {
			known[name] = true
		}
	}
	for name := range fields {
		if !known[name] {
			return fmt.Errorf("unknown policy field %q", name)
		}
	}
	return nil
}

func checkJSONKeys(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("policy nesting is too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	seen := map[string]bool{}
	for decoder.More() {
		if delimiter == '{' {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return fmt.Errorf("duplicate or invalid policy field %q", name)
			}
			seen[name] = true
		}
		if err := checkJSONKeys(decoder, depth+1); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}
