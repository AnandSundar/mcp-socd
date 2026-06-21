package catalog

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
)

// Catalog is the merged, in-memory view of starter plus custom catalog
// entries keyed by Action.Name. Lookups in U3 and U5 are O(1) over the
// underlying map; iteration order is not guaranteed.
//
// A nil Catalog value is not valid; use New (which seeds with Starter)
// or zero-value via &Catalog{} plus Add if the caller wants the empty
// set explicitly.
type Catalog struct {
	// Actions is the merged set. Mutable; the loader appends to it
	// during LoadCustom and starter seeding during New.
	Actions map[string]Action
}

// New returns a Catalog seeded with the five starter actions from R4.
// The returned Catalog owns its copies of the starter Actions; mutating
// them does not affect subsequent New calls.
func New() *Catalog {
	c := &Catalog{Actions: make(map[string]Action, len(starterNames()))}
	for _, a := range Starter() {
		c.Actions[a.Name] = a
	}
	return c
}

// starterNames returns the canonical sorted list of starter action
// names. Used only for the test that asserts exactly five actions.
func starterNames() []string {
	return []string{
		"isolate_endpoint",
		"block_user_account",
		"rotate_api_key",
		"submit_edr_query",
		"enrich_ioc",
	}
}

// ErrActionExists is returned when a custom YAML file declares an
// action whose Name is already in the merged catalog (either a starter
// or a previously-loaded custom). The loader does not silently
// override, so an operator who wants to replace a starter must
// explicitly remove it first via Remove.
var ErrActionExists = errors.New("catalog: action already exists")

// ErrActionNotFound is returned by Remove when the named action is not
// in the catalog.
var ErrActionNotFound = errors.New("catalog: action not found")

// LoadCustomFile reads a YAML file containing a custom-action document
// and merges the declared actions into c. Each action is validated
// against the same contract as a starter action (Validate) and its
// JSON-Schema is compiled before insertion.
//
// The YAML format is one of:
//
//	# Single action
//	name: my_custom_action
//	description: ...
//	params: [...]
//	blast_radius: 3
//	ocsf_audit_shape:
//	  title: ...
//	  severity_id: 3
//	  types: ["soc-action"]
//	input_schema: |
//	  { ...JSON-Schema text... }
//
//	# Multiple actions
//	actions:
//	  - name: ...
//	    ...
//
// Errors are wrapped with the file path so multi-file loads can be
// traced back to the offending source.
func (c *Catalog) LoadCustomFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read catalog %s: %w", path, err)
	}
	actions, err := parseCustomYAML(data)
	if err != nil {
		return fmt.Errorf("parse catalog %s: %w", path, err)
	}
	for _, a := range actions {
		if err := c.addValidated(a); err != nil {
			return fmt.Errorf("load catalog %s: %w", path, err)
		}
	}
	return nil
}

// LoadCustomBytes parses and merges a custom-action document from
// in-memory bytes. Used by tests and by the SIGHUP hot-reload path in
// the CLI (which reads the file then forwards the bytes here so the
// test path and the runtime path share parse + validate logic).
func (c *Catalog) LoadCustomBytes(data []byte) error {
	actions, err := parseCustomYAML(data)
	if err != nil {
		return fmt.Errorf("parse custom catalog: %w", err)
	}
	for _, a := range actions {
		if err := c.addValidated(a); err != nil {
			return fmt.Errorf("load custom catalog: %w", err)
		}
	}
	return nil
}

// parseCustomYAML accepts either a single-action document (top-level
// fields: name, description, ...) or a multi-action document (top-level
// `actions:` list). Returns the parsed actions in declaration order.
//
// We probe the top-level keys via yaml.Node to choose the shape; in
// multi-action mode we round-trip each child through yaml.Encoder to
// preserve the inline JSON-Schema string, which a flat struct
// unmarshal would silently discard because the Action struct does not
// carry the raw input_schema field.
func parseCustomYAML(data []byte) ([]Action, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("yaml unmarshal: %w", err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil, errors.New("catalog document is empty")
	}
	top := root.Content[0]
	if top.Kind != yaml.MappingNode {
		return nil, errors.New("catalog document must be a mapping at the top level")
	}

	if hasTopLevelKey(top, "actions") {
		return parseMultiAction(top)
	}
	return parseSingleAction(data)
}

// hasTopLevelKey scans a mapping node for the given scalar key.
func hasTopLevelKey(m *yaml.Node, key string) bool {
	for i := 0; i+1 < len(m.Content); i += 2 {
		k := m.Content[i]
		if k.Kind == yaml.ScalarNode && k.Value == key {
			return true
		}
	}
	return false
}

// parseSingleAction decodes a top-level single-action document.
func parseSingleAction(data []byte) ([]Action, error) {
	var a Action
	if err := decodeSingleInto(&a, data); err != nil {
		return nil, err
	}
	return []Action{a}, nil
}

// parseMultiAction decodes the `actions:` list under a known top
// mapping node. Each child is re-encoded to YAML bytes before being
// passed to decodeSingleInto so the JSON-Schema string round-trips.
func parseMultiAction(top *yaml.Node) ([]Action, error) {
	var rawList []*yaml.Node
	for i := 0; i+1 < len(top.Content); i += 2 {
		if top.Content[i].Value == "actions" {
			rawList = top.Content[i+1].Content
			break
		}
	}
	if len(rawList) == 0 {
		return nil, errors.New("catalog document declares no actions (empty actions list)")
	}
	out := make([]Action, 0, len(rawList))
	for i, n := range rawList {
		var buf bytes.Buffer
		enc := yaml.NewEncoder(&buf)
		enc.SetIndent(2)
		if err := enc.Encode(n); err != nil {
			_ = enc.Close()
			return nil, fmt.Errorf("action[%d]: yaml re-encode: %w", i, err)
		}
		if err := enc.Close(); err != nil {
			return nil, fmt.Errorf("action[%d]: yaml re-encode close: %w", i, err)
		}
		var a Action
		if err := decodeSingleInto(&a, buf.Bytes()); err != nil {
			return nil, fmt.Errorf("action[%d]: %w", i, err)
		}
		out = append(out, a)
	}
	return out, nil
}

// decodeSingleInto decodes a single YAML action document into a,
// compiling its input_schema field into a *jsonschema.Schema and
// validating the result.
//
// schemaText may be empty (legacy or schema-less actions); the runtime
// will then refuse to validate arguments. We reject that here so the
// catalog does not silently accept an action that cannot be validated
// at runtime.
func decodeSingleInto(a *Action, raw []byte) error {
	var doc struct {
		Name           string     `yaml:"name"`
		Description    string     `yaml:"description"`
		Params         []Param    `yaml:"params"`
		BlastRadius    int        `yaml:"blast_radius"`
		OCSFAuditShape AuditShape `yaml:"ocsf_audit_shape"`
		InputSchema    string     `yaml:"input_schema"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("yaml unmarshal action: %w", err)
	}
	a.Name = doc.Name
	a.Description = doc.Description
	a.Params = doc.Params
	a.BlastRadius = doc.BlastRadius
	a.OCSFAuditShape = doc.OCSFAuditShape

	if strings.TrimSpace(doc.InputSchema) == "" {
		return fmt.Errorf("action %q: input_schema is required", a.Name)
	}
	compiled, rawSchema, err := compileUserSchema(a.Name, doc.InputSchema)
	if err != nil {
		return err
	}
	a.InputSchema = compiled
	a.RawSchema = rawSchema
	return a.Validate()
}

// compileUserSchema registers and compiles a user-supplied JSON-Schema
// string. The action name is folded into the in-binary URL so two
// custom actions cannot accidentally collide on the compiler's URL
// space.
func compileUserSchema(action, schemaText string) (*jsonschema.Schema, []byte, error) {
	url := schemaURL("custom/" + action)
	body := []byte(schemaText)
	if err := schemaCompiler.AddResource(url, bytes.NewReader(body)); err != nil {
		return nil, nil, fmt.Errorf("action %q: register input_schema: %w", action, err)
	}
	compiled, err := schemaCompiler.Compile(url)
	if err != nil {
		return nil, nil, fmt.Errorf("action %q: compile input_schema: %w", action, err)
	}
	return compiled, body, nil
}

// addValidated checks for name collisions and validates the action
// before insertion. The error wraps ErrActionExists for collision
// detection via errors.Is.
func (c *Catalog) addValidated(a Action) error {
	if _, exists := c.Actions[a.Name]; exists {
		return fmt.Errorf("%w: %q", ErrActionExists, a.Name)
	}
	if err := a.Validate(); err != nil {
		return err
	}
	c.Actions[a.Name] = a
	return nil
}

// Remove deletes an action from the catalog. Used by the hot-reload
// path when an operator deletes a starter or custom entry from disk.
func (c *Catalog) Remove(name string) error {
	if _, exists := c.Actions[name]; !exists {
		return fmt.Errorf("%w: %q", ErrActionNotFound, name)
	}
	delete(c.Actions, name)
	return nil
}

// Get returns the action with the given name and whether it exists.
// Lookups are O(1) over the underlying map.
func (c *Catalog) Get(name string) (Action, bool) {
	a, ok := c.Actions[name]
	return a, ok
}

// Validate runs an arguments object against the action's compiled
// JSON-Schema. Returns nil on success, or a structured error on
// failure. The error wraps ErrSchemaViolation (when the schema
// validator reports one) so callers can branch on errors.Is.
//
// args is expected to be a map[string]any, decoded from the agent's
// JSON-RPC arguments field. Other shapes are rejected with a clear
// error rather than a panic, because the agent may supply any JSON.
func (c *Catalog) Validate(actionName string, args any) error {
	a, ok := c.Actions[actionName]
	if !ok {
		return fmt.Errorf("%w: %q", ErrActionNotFound, actionName)
	}
	if a.InputSchema == nil {
		return fmt.Errorf("action %q has no compiled input_schema; cannot validate", actionName)
	}
	if err := a.InputSchema.Validate(args); err != nil {
		return fmt.Errorf("%w: %s", ErrSchemaViolation, formatSchemaErr(err))
	}
	return nil
}

// ErrSchemaViolation is returned when an arguments object fails the
// action's JSON-Schema validation. Callers may branch on errors.Is.
var ErrSchemaViolation = errors.New("catalog: schema violation")

// formatSchemaErr reduces a santhosh-tekuri validation error to a
// single-line, human-readable string. The library returns rich
// *jsonschema.ValidationError values; we surface the most-specific
// leaf cause plus its instance location so operators can see which
// argument failed.
func formatSchemaErr(err error) string {
	var verr *jsonschema.ValidationError
	if !errors.As(err, &verr) {
		return err.Error()
	}
	leaf := verr
	for len(leaf.Causes) > 0 {
		leaf = leaf.Causes[0]
	}
	msg := leaf.Message
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = msg[:i]
	}
	if leaf.InstanceLocation == "" {
		return msg
	}
	return leaf.InstanceLocation + ": " + msg
}
